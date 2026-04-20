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

package org.apache.logging.log4j.core.net;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.logging.log4j.core.appender.AbstractManager;
import org.apache.logging.log4j.core.appender.ManagerFactory;
import org.apache.logging.log4j.core.util.JndiCloser;
import org.apache.logging.log4j.util.PropertiesUtil;

/**
 * Manages a JNDI {@link javax.naming.Context}.
 *
 * <p>As of Log4j 2.16.0, JNDI features are disabled by default as a mitigation for
 * CVE-2021-44228 (Log4Shell). To re-enable, set the system property
 * {@code log4j2.enableJndi=true}. Allowed JNDI protocols can be configured via
 * {@code log4j2.allowedJndiProtocols} (default: {@code java}) and allowed LDAP hosts
 * via {@code log4j2.allowedLdapHosts} (default: {@code localhost}).</p>
 *
 * @since 2.1
 */
public class JndiManager extends AbstractManager {

    private static final JndiManagerFactory FACTORY = new JndiManagerFactory();
    static final String JNDI_MANAGER_ENABLED_PROPERTY = "log4j2.enableJndi";
    private static final String ALLOWED_PROTOCOLS_PROPERTY = "log4j2.allowedJndiProtocols";
    private static final String ALLOWED_HOSTS_PROPERTY = "log4j2.allowedLdapHosts";
    private static final List<String> ALLOWED_PROTOCOLS;
    private static final List<String> ALLOWED_HOSTS;

    static {
        final String protocols = PropertiesUtil.getProperties().getStringProperty(
                ALLOWED_PROTOCOLS_PROPERTY, "java");
        ALLOWED_PROTOCOLS = Arrays.asList(protocols.split("\\s*,\\s*"));
        final String hosts = PropertiesUtil.getProperties().getStringProperty(
                ALLOWED_HOSTS_PROPERTY, "localhost,127.0.0.1,0:0:0:0:0:0:0:1,::1");
        ALLOWED_HOSTS = Arrays.asList(hosts.split("\\s*,\\s*"));
    }

    /**
     * Returns whether JNDI is enabled via the {@code log4j2.enableJndi} system property.
     *
     * @return {@code true} if JNDI is enabled, {@code false} otherwise.
     */
    public static boolean isJndiEnabled() {
        return PropertiesUtil.getProperties().getBooleanProperty(JNDI_MANAGER_ENABLED_PROPERTY, false);
    }

    private final Context context;

    private JndiManager(final String name, final Context context) {
        super(null, name);
        this.context = context;
    }

    /**
     * Gets the default JndiManager using the default {@link javax.naming.InitialContext}.
     *
     * @return the default JndiManager
     */
    public static JndiManager getDefaultManager() {
        return getManager(JndiManager.class.getName(), FACTORY, null);
    }

    /**
     * Gets a named JndiManager using the default {@link javax.naming.InitialContext}.
     *
     * @param name the name of the JndiManager instance to create or use if available
     * @return a default JndiManager
     */
    public static JndiManager getDefaultManager(final String name) {
        return getManager(name, FACTORY, null);
    }

    /**
     * Gets a JndiManager with the provided configuration information.
     *
     * @param initialContextFactoryName Fully qualified class name of an implementation of
     *                                  {@link javax.naming.spi.InitialContextFactory}.
     * @param providerURL               The provider URL to use for the JNDI connection (specific to the above factory).
     * @param urlPkgPrefixes            A colon-separated list of package prefixes for the class name of the factory
     *                                  class that will create a URL context factory
     * @param securityPrincipal         The name of the identity of the Principal.
     * @param securityCredentials       The security credentials of the Principal.
     * @param additionalProperties      Any additional JNDI environment properties to set or {@code null} for none.
     * @return the JndiManager for the provided parameters.
     */
    public static JndiManager getJndiManager(final String initialContextFactoryName,
            final String providerURL,
            final String urlPkgPrefixes,
            final String securityPrincipal,
            final String securityCredentials,
            final Properties additionalProperties) {
        final Properties properties = createProperties(initialContextFactoryName, providerURL, urlPkgPrefixes,
                securityPrincipal, securityCredentials, additionalProperties);
        return getManager(createManagerName(), FACTORY, properties);
    }

    /**
     * Gets a JndiManager with the provided configuration information.
     *
     * @param properties JNDI properties, usually created by calling {@link #createProperties(String, String, String, String, String, Properties)}.
     * @return the JndiManager for the provided parameters.
     * @see #createProperties(String, String, String, String, String, Properties)
     * @since 2.9
     */
    public static JndiManager getJndiManager(final Properties properties) {
        return getManager(createManagerName(), FACTORY, properties);
    }

    private static String createManagerName() {
        return JndiManager.class.getName() + '@' + JndiManager.class.hashCode();
    }

    /**
     * Creates JNDI Properties with the provided configuration information.
     *
     * @param initialContextFactoryName
     *            Fully qualified class name of an implementation of {@link javax.naming.spi.InitialContextFactory}.
     * @param providerURL
     *            The provider URL to use for the JNDI connection (specific to the above factory).
     * @param urlPkgPrefixes
     *            A colon-separated list of package prefixes for the class name of the factory class that will create a
     *            URL context factory
     * @param securityPrincipal
     *            The name of the identity of the Principal.
     * @param securityCredentials
     *            The security credentials of the Principal.
     * @param additionalProperties
     *            Any additional JNDI environment properties to set or {@code null} for none.
     * @return the Properties for the provided parameters.
     * @since 2.9
     */
    public static Properties createProperties(final String initialContextFactoryName, final String providerURL,
            final String urlPkgPrefixes, final String securityPrincipal, final String securityCredentials,
            final Properties additionalProperties) {
        if (initialContextFactoryName == null) {
            return null;
        }
        final Properties properties = new Properties();
        properties.setProperty(Context.INITIAL_CONTEXT_FACTORY, initialContextFactoryName);
        if (providerURL != null) {
            properties.setProperty(Context.PROVIDER_URL, providerURL);
        } else {
            LOGGER.warn("The JNDI InitialContextFactory class name [{}] was provided, but there was no associated "
                    + "provider URL. This is likely to cause problems.", initialContextFactoryName);
        }
        if (urlPkgPrefixes != null) {
            properties.setProperty(Context.URL_PKG_PREFIXES, urlPkgPrefixes);
        }
        if (securityPrincipal != null) {
            properties.setProperty(Context.SECURITY_PRINCIPAL, securityPrincipal);
            if (securityCredentials != null) {
                properties.setProperty(Context.SECURITY_CREDENTIALS, securityCredentials);
            } else {
                LOGGER.warn("A security principal [{}] was provided, but with no corresponding security credentials.",
                        securityPrincipal);
            }
        }
        if (additionalProperties != null) {
            properties.putAll(additionalProperties);
        }
        return properties;
    }

    @Override
    protected boolean releaseSub(final long timeout, final TimeUnit timeUnit) {
        return JndiCloser.closeSilently(this.context);
    }

    /**
     * Looks up a named object through this JNDI context.
     *
     * <p>This method validates the URI scheme against the allowed protocols list
     * ({@code log4j2.allowedJndiProtocols}). LDAP/LDAPS URIs are also validated
     * against the allowed hosts list ({@code log4j2.allowedLdapHosts}).</p>
     *
     * @param name name of the object to look up.
     * @param <T>  the type of the object.
     * @return the named object if it could be located.
     * @throws  NamingException if a naming exception is encountered
     */
    @SuppressWarnings("unchecked")
    public <T> T lookup(final String name) throws NamingException {
        try {
            final URI uri = new URI(name);
            final String scheme = uri.getScheme();
            if (scheme != null && !ALLOWED_PROTOCOLS.contains(scheme.toLowerCase())) {
                LOGGER.warn("JNDI URI '{}' uses a protocol that is not allowed. Allowed protocols: {}.",
                        name, ALLOWED_PROTOCOLS);
                return null;
            }
            if (scheme != null && (scheme.equalsIgnoreCase("ldap") || scheme.equalsIgnoreCase("ldaps"))) {
                final String host = uri.getHost();
                if (host != null && !ALLOWED_HOSTS.contains(host)) {
                    LOGGER.warn("JNDI URI '{}' connects to a host that is not allowed. Allowed hosts: {}.",
                            name, ALLOWED_HOSTS);
                    return null;
                }
            }
        } catch (final URISyntaxException e) {
            // Not a URI — only allow if no scheme is present (plain name)
        }
        return (T) this.context.lookup(name);
    }

    private static class JndiManagerFactory implements ManagerFactory<JndiManager, Properties> {

        @Override
        public JndiManager createManager(final String name, final Properties data) {
            try {
                return new JndiManager(name, new InitialContext(data));
            } catch (final NamingException e) {
                LOGGER.error("Error creating JNDI InitialContext.", e);
                return null;
            }
        }
    }

    @Override
    public String toString() {
        return "JndiManager [context=" + context + ", count=" + count + "]";
    }

}
