/*******************************************************************************
 * Copyright (c) 2000, 2003 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *     Alex Blewitt - implementation of GServer protocol
 *******************************************************************************/
package org.eclipse.team.internal.ccvs.core.connection;
 
import org.eclipse.team.internal.ccvs.core.ICVSRepositoryLocation;
import org.eclipse.team.internal.ccvs.core.IConnectionMethod;
import org.eclipse.team.internal.ccvs.core.IServerConnection;
public class GServerConnectionMethod implements IConnectionMethod {
	/**
	 * @see IConnectionMethod#createConnection(ICVSRepositoryLocation, String)
	 */
	public IServerConnection createConnection(ICVSRepositoryLocation location, String password) {
		return new GServerConnection(location, password);
	}
	/**
	 * @see IConnectionMethod#getName()
	 */
	public String getName() {
		return "gserver";//$NON-NLS-1$
	}
	
	/**
	 * @see org.eclipse.team.internal.ccvs.core.IConnectionMethod#disconnect(org.eclipse.team.internal.ccvs.core.ICVSRepositoryLocation)
	 */
	public void disconnect(ICVSRepositoryLocation location) {
	}
}
