// Copyright (c) 2005 Alex Blewitt
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v1.0
// which accompanies this distribution, and is available at
// http://www.eclipse.org/legal/epl-v10.html
//
// Contributors:
// Alex Blewitt - Initial API and implementation
//
package org.eclipse.team.internal.ccvs.core.connection;
import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
/**
 * Allows a kerberos login attempt to use the userid/password already given in
 * the dialog box if required.
 */
public class GServerCallbackHandler implements CallbackHandler {
	private String username;
	private char[] password;
	public GServerCallbackHandler(String username, String password) {
		this.username = username;
		int length = password.length();
		this.password = new char[length];
		password.getChars(0, length, this.password, 0);
	}
	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
	 */
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		System.err.println("Handler being called");
		for (int i = 0; i < callbacks.length; i++) {
			Callback callback = callbacks[i];
			if (callback instanceof NameCallback) {
				((NameCallback)callback).setName(username);
			}
			if (callback instanceof PasswordCallback) {
				((PasswordCallback)callback).setPassword(password);
			}
		}
	}
	public void resetPassword() {
		if (password != null)
			for(int i=0;i<password.length;i++)
				password[i] = ' ';
		password = null;
	}
}
