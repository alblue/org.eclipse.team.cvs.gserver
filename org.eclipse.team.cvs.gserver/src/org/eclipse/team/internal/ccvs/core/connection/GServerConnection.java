/*******************************************************************************
 * Copyright (c) 2000, 2004 IBM Corporation and others. All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html Contributors:
 * 
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *     Alex Blewitt - implementation of GServer protocol
 ******************************************************************************/
package org.eclipse.team.internal.ccvs.core.connection;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.osgi.util.NLS;
import org.eclipse.team.internal.ccvs.core.CVSMessages;
import org.eclipse.team.internal.ccvs.core.ICVSRepositoryLocation;
import org.eclipse.team.internal.ccvs.core.IServerConnection;
import org.eclipse.team.internal.ccvs.core.util.Util;
import org.eclipse.team.internal.core.streams.PollingInputStream;
import org.eclipse.team.internal.core.streams.PollingOutputStream;
import org.eclipse.team.internal.core.streams.TimeoutOutputStream;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
/**
 * A connection used to talk to an cvs gserver.
 * TODO Refactor this and Pserver into common superclass
 */
public class GServerConnection implements IServerConnection {
	public static final char NEWLINE = '\n';
	/** default CVS pserver port */
	private static final int DEFAULT_PORT = 2401;
	/** error line indicators */
	private static final char ERROR_CHAR = 'E';
	private static final String ERROR_MESSAGE = "error 0";//$NON-NLS-1$
	private static final String NO_SUCH_USER = "no such user";//$NON-NLS-1$
	/** Communication strings */
	private static final String BEGIN = "BEGIN GSSAPI REQUEST";//$NON-NLS-1$
	private static final String LOGIN_OK = "I LOVE YOU";//$NON-NLS-1$
	private static final String LOGIN_FAILED = "I HATE YOU";//$NON-NLS-1$
	private ICVSRepositoryLocation cvsroot;
	private Socket fSocket;
	private InputStream inputStream;
	private OutputStream outputStream;
	private GServerCallbackHandler authenticator;
	/**
	 * @see Connection#doClose()
	 */
	public void close() throws IOException {
		try {
			if (authenticator != null) {
				authenticator.resetPassword();
			}
			if (inputStream != null)
				inputStream.close();
		} finally {
			inputStream = null;
			try {
				if (outputStream != null)
					outputStream.close();
			} finally {
				outputStream = null;
				try {
					if (fSocket != null)
						fSocket.close();
				} finally {
					fSocket = null;
				}
			}
		}
	}
	/**
	 * @see Connection#doOpen()
	 */
	public void open(IProgressMonitor monitor) throws IOException,
			CVSAuthenticationException {
		// TODO Externalise
		monitor.subTask("Authenticating using gserver");
		monitor.worked(1);
		fSocket = createSocket(monitor);
		boolean connected = false;
		try {
			this.inputStream = new BufferedInputStream(new PollingInputStream(
					fSocket.getInputStream(), cvsroot.getTimeout(), monitor));
			this.outputStream = new PollingOutputStream(
					new TimeoutOutputStream(fSocket.getOutputStream(),
							8192 /* bufferSize */, 1000 /* writeTimeout */,
							1000 /* closeTimeout */), cvsroot.getTimeout(),
					monitor);
			authenticate();
			connected = true;
		} finally {
			if (!connected)
				cleanUpAfterFailedConnection();
		}
	}
	/**
	 * @see Connection#getInputStream()
	 */
	public InputStream getInputStream() {
		return inputStream;
	}
	/**
	 * @see Connection#getOutputStream()
	 */
	public OutputStream getOutputStream() {
		return outputStream;
	}
	/**
	 * Creates a new <code>PServerConnection</code> for the given cvs root.
	 */
	GServerConnection(ICVSRepositoryLocation cvsroot, String password) {
		this.cvsroot = cvsroot;
		this.authenticator = new GServerCallbackHandler(cvsroot.getUsername(),password);
	}
	/**
	 * Does the actual authentification.
	 */
	private void authenticate() throws IOException, CVSAuthenticationException {
		OutputStream out = getOutputStream();
		InputStream in = getInputStream();
		StringBuffer request = new StringBuffer();
		request.append(BEGIN);
		request.append(NEWLINE);
		out.write(request.toString().getBytes());
		out.flush();
		gssapiAuthenticate(out, in);
		request.setLength(0);
		String line = Connection.readLine(cvsroot, in).trim();
		// Return if we succeeded
		if (LOGIN_OK.equals(line))
			return;
		// Otherwise, determine the type of error
		if (line.length() == 0) {
			throw new IOException(CVSMessages.PServerConnection_noResponse);//$NON-NLS-1$
		}
		// Accumulate a message from the error (E) stream
		String message = "";//$NON-NLS-1$
		String separator = ""; //$NON-NLS-1$
		while (line.length() > 0 && line.charAt(0) == ERROR_CHAR) {
			if (line.length() > 2) {
				message += separator + line.substring(2);
				separator = " "; //$NON-NLS-1$
			}
			line = Connection.readLine(cvsroot, getInputStream());
		}
		// If the last line is the login failed (I HATE YOU) message, return
		// authentication failure
		if (LOGIN_FAILED.equals(line)) {
			if (message.length() == 0) {
				throw new CVSAuthenticationException(
						CVSMessages.PServerConnection_loginRefused,
						CVSAuthenticationException.RETRY);//$NON-NLS-1$
			} else {
				throw new CVSAuthenticationException(message,
						CVSAuthenticationException.RETRY);
			}
		}
		// Remove leading "error 0"
		if (line.startsWith(ERROR_MESSAGE))
			message += separator + line.substring(ERROR_MESSAGE.length() + 1);
		else
			message += separator + line;
		if (message.indexOf(NO_SUCH_USER) != -1)
			throw new CVSAuthenticationException(NLS.bind(
					CVSMessages.PServerConnection_invalidUser,
					(new Object[] { message })),
					CVSAuthenticationException.RETRY);//$NON-NLS-1$
		throw new IOException(NLS.bind(
				CVSMessages.PServerConnection_connectionRefused,
				(new Object[] { message })));//$NON-NLS-1$
	}
	/**
	 * Performs GSSAPI authentication by sending requests/responses to the input streams.
	 * The method writes the length of each token as a 2-byte number, followed by
	 * the byte data. It consumes data from the input stream by the reverse process.
	 * If there is a problem with authorisation, a CVSAuthenticationException is thrown
	 * @param out the output stream to write data to (remote CVS server)
	 * @param in the input stream to read data from (remote CVS server)
	 * @throws IOException if there is a problem communicating with the input/output streams
	 * @throws CVSAuthenticationException if the authorisation fails
	 */
	private void gssapiAuthenticate(OutputStream out, InputStream in)
			throws IOException, CVSAuthenticationException {
		try {
			System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");//$NON-NLS-1$ $NON-NLS-2$
//			try {
//				// This will generate the kerberos ticket for us if we don't have it
//				// TODO Finish this so that it works
//				LoginContext lc = new LoginContext("Eclipse",authenticator);//$NON-NLS-1$
//				System.err.println("Trying to log in");
//				lc.login();
//				System.err.println("Logged in");
//			} catch (LoginException e) {
//				throw new CVSAuthenticationException("Problem logging in",CVSAuthenticationException.RETRY,e);
//			}
			GSSManager manager = GSSManager.getInstance();
			Oid kerberos5  = new Oid("1.2.840.113554.1.2.2");//$NON-NLS-1$
			GSSName cvsSlashServer = manager.createName("cvs/" + cvsroot.getHost(),null);//$NON-NLS-1$
			GSSContext context = manager.createContext(cvsSlashServer, kerberos5, null,
					GSSContext.INDEFINITE_LIFETIME);
			byte[] inToken = new byte[0];
			while (!context.isEstablished()) {
				byte[] outToken = context.initSecContext(inToken, 0,
						inToken.length);
				if (outToken == null || outToken.length == 0)
					break;
				inToken = sendToken(out, in, outToken);
			}
		} catch (GSSException e) {
			throw new CVSAuthenticationException(
					CVSMessages.PServerConnection_connectionRefused,
					CVSAuthenticationException.NOT_AUTHORIZED, e);
		}
	}
	/**
	 * Write a single token using the GSSAPI mechanism; two bytes (MSB) length, followed by
	 * that many bytes; read a response (two bytes length; then the list) in return.
	 * @param out the output stream to write to
	 * @param in the input stream to read from
	 * @param outToken the token to be sent
	 * @throws IOException if an error occurs
	 */
	private byte[] sendToken(OutputStream out, InputStream in, byte[] outToken)
			throws IOException {
		// 2 byte MSB length, followed by token in both directions
		out.write((outToken.length >> 8) & 0xff);
		out.write(outToken.length & 0xff);
		out.write(outToken, 0, outToken.length);
		out.flush();
		int len = (in.read() << 8) | in.read();
		byte[] inToken = new byte[len];
		// TODO Read token fully properly - this may only load some of it
		if (len != in.read(inToken, 0, len))
			throw new RuntimeException("Failed to load complete token");
		return inToken;
	}
	/*
	 * Called if there are exceptions when connecting. This method makes sure
	 * that all connections are closed.
	 */
	private void cleanUpAfterFailedConnection() throws IOException {
		try {
			if (inputStream != null)
				inputStream.close();
		} finally {
			try {
				if (outputStream != null)
					outputStream.close();
			} finally {
				try {
					if (fSocket != null)
						fSocket.close();
				} finally {
					fSocket = null;
				}
			}
		}
	}
	/**
	 * Creates the actual socket
	 */
	protected Socket createSocket(IProgressMonitor monitor) throws IOException {
		// Determine what port to use
		int port = cvsroot.getPort();
		if (port == ICVSRepositoryLocation.USE_DEFAULT_PORT)
			port = DEFAULT_PORT;
		// Make the connection
		Socket result;
		try {
			result = Util.createSocket(cvsroot.getHost(), port, monitor);
			// Bug 36351: disable buffering and send bytes immediately
			result.setTcpNoDelay(true);
		} catch (InterruptedIOException e) {
			// If we get this exception, chances are the host is not responding
			throw new InterruptedIOException(NLS.bind(
					CVSMessages.PServerConnection_socket,
					(new Object[] { cvsroot.getHost() })));//$NON-NLS-1$
		}
		result.setSoTimeout(1000); // 1 second between timeouts
		return result;
	}
}
