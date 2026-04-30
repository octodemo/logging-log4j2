/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.apache.logging.log4j.core.lookup;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * JndiLookupTest
 */
public class JndiLookupTest {

    /**
     * Verifies that JNDI lookups are disabled by default (CVE-2021-44228).
     */
    @Test
    public void testJndiDisabledByDefault() {
        assertFalse("JNDI lookup must be disabled by default (CVE-2021-44228)",
                JndiLookup.isJndiEnabled());
    }

    /**
     * Verifies that a lookup call returns null when JNDI is disabled.
     */
    @Test
    public void testLookupReturnsNullWhenDisabled() {
        final StrLookup lookup = new JndiLookup();
        // JNDI is disabled by default; all lookups should return null
        assertNull(lookup.lookup("logging/context-name"));
        assertNull(lookup.lookup(JndiLookup.CONTAINER_JNDI_RESOURCE_PATH_PREFIX + "logging/context-name"));
    }
}
