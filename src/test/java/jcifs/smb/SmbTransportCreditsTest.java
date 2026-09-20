/*
 * Copyright (C) 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package jcifs.smb;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.concurrent.Semaphore;

import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.util.transport.Request;

/** Exercises transport credit consumption/replenishment without opening a socket. */
public class SmbTransportCreditsTest {
    private static final class ReplyTransport extends SmbTransportImpl {
        private final int grant;

        ReplyTransport ( CIFSContext context, int grant ) {
            super(context, null, 445, null, 0, false);
            this.grant = grant;
        }

        @Override
        public boolean isDisconnected () {
            return false;
        }

        @Override
        protected void doSend ( Request request ) {
            ServerMessageBlock2Response response = (ServerMessageBlock2Response) request.getResponse();
            response.setCredit(this.grant);
            response.received();
        }
    }

    @Test
    public void replenishOnlyServerGrantedCredits () throws Exception {
        Configuration config = mock(Configuration.class);
        when(config.getMaximumBufferSize()).thenReturn(65536);
        when(config.getResponseTimeout()).thenReturn(1000);
        CIFSContext context = mock(CIFSContext.class);
        when(context.getConfig()).thenReturn(config);
        for ( int grant : new int[] { 0, 1, 16, 20 } ) {
            ReplyTransport transport = new ReplyTransport(context, grant);
            Field creditField = SmbTransportImpl.class.getDeclaredField("credits");
            creditField.setAccessible(true);
            Semaphore credits = (Semaphore) creditField.get(transport);
            credits.release(16); // 17 available: a 16-credit request leaves one unused.
            Field mtuField = SmbTransportImpl.class.getDeclaredField("largeMtu");
            mtuField.setAccessible(true);
            mtuField.setBoolean(transport, true);
            Field smb2Field = SmbTransportImpl.class.getDeclaredField("smb2");
            smb2Field.setAccessible(true);
            smb2Field.setBoolean(transport, true);

            Smb2ReadRequest request = new Smb2ReadRequest(config, new byte[16], new byte[1024 * 1024], 0);
            request.setReadLength(1024 * 1024);
            try {
                transport.sendrecv(request, null, Collections.<RequestParam>emptySet());
                assertEquals("Server grant " + grant, 1 + grant, credits.availablePermits());
                assertEquals(16, request.getCreditCharge());
            }
            finally {
                transport.release();
            }
        }
    }
}
