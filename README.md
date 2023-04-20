# Operation
## Start Stop RH SSO Cluster Node
### Start
```
sudo service jboss-eap-rhel start
OR
domain.sh --host-config=host-master.xml
domain.sh --host-config=host-slave.xml
```
### Stop
```
sudo service jboss-eap-rhel stop
OR
kill -9 domain.sh
```
### jboss-cli after disable http (only https)
```
jboss-cli.sh --connect --controller=remote+https://rhsso:9443
```
### kcadm to keycloak admin-cli
```
cd /opt/rh/sso/server/bin

>> For HTTP
kcadm.sh config credentials --server http://rhsso:8080/auth --realm master --user admin --client admin-cli

>> For HTTPS (if disable http)
kcadm.sh config truststore --trustpass Changeit /opt/rh/sso/keystore/keystore.jks
kcadm.sh config credentials --server https://rhsso:8443/auth --realm master --user admin --client admin-cli

>> Get clients config
kcadm.sh get clients

>> Enabled/Disabled realm
kcadm.sh update realms/MBIXRealm -s enabled=true
```

# Install RHSSO

```
$ sudo yum install jdk-11.0.8_linux-x64

$ mkdir -p /opt/rh/sso/keystore
$ unzip rh-sso-7.4.zip -d /opt/rh/sso
$ cd /opt/rh/sso
$ mv rh-sso-7.4 7.4
$ ln -s 7.4 server
$ cd server/bin
$ jboss-cli.sh
$ patch apply <path-to-zip>/rh-sso-7.4.2-patch.zip

$ vi /etc/sysctl.d/99-sysctl.conf

>>> ADD Below At Bottom
# Allow a 25MB UDP receive buffer for JGroups
net.core.rmem_max = 26214400
# Allow a 1MB UDP send buffer for JGroups
net.core.wmem_max = 1048576

```

# Config RH EAP for RH SSO Cluster.
## Config Domain Comtroller to manage config in one point
### Remove "auth-server-standalone" and "load-balancer" profile sub-system
```
$ cd /opt/rh/sso/server/bin
$ domain.sh --host-config=host-master.xml -b localhost
jboss-cli.sh --connect --controller=localhost:9990
/profile=auth-server-standalone:remove
/profile=load-balancer:remove
```

### Remove socket-binding-group "load-balancer-sockets"
```
/socket-binding-group=load-balancer-sockets:remove

OR manual remove
        <!-- <socket-binding-group name="load-balancer-sockets" default-interface="public">
            <!-- Needed for server groups using the 'load-balancer' profile  -->
            <socket-binding name="http" port="${jboss.http.port:8080}"/>
            <socket-binding name="https" port="${jboss.https.port:8443}"/>
            <socket-binding name="mcmp-management" interface="private" port="${jboss.mcmp.port:8090}"/>
            <socket-binding name="modcluster" interface="private" multicast-address="${jboss.modcluster.multicast.address:224.0.1.105}" multicast-port="23364"/>
        </socket-binding-group> -->
```

### Remove server-group "load-balancer-group" 
```
/server-group=load-balancer-group:remove

OR manual remove
        <!-- <server-group name="load-balancer-group" profile="load-balancer">
            <jvm name="default">
                <heap size="64m" max-size="512m"/>
            </jvm>
            <socket-binding-group ref="load-balancer-sockets"/>
        </server-group> -->
```

### Change ExampleDS to LocalDS
```
            <subsystem xmlns="urn:jboss:domain:datasources:5.0">
                <datasources>
                    <datasource jndi-name="java:jboss/datasources/LocalDS" pool-name="LocalDS" enabled="true" use-java-context="true" statistics-enabled="${wildfly.datasources.statistics-enabled:${wildfly.statistics-enabled:false}}">
```
And
```
                <default-bindings context-service="java:jboss/ee/concurrency/context/default" datasource="java:jboss/datasources/LocalDS" managed-executor-service="java:jboss/ee/concurrency/executor/default" managed-scheduled-executor-service="java:jboss/ee/concurrency/scheduler/default" managed-thread-factory="java:jboss/ee/concurrency/factory/default"/>
```

### Change KeycloakDS connection URL add pool size and user/password
```
                    <connection-url>jdbc:postgresql://rhsso.dbhost:5432/keycloak</connection-url>
                        <driver>postgresql</driver>
                        <pool>
                            <max-pool-size>20</max-pool-size>
                        </pool>
                        <security>
                            <user-name>postgres</user-name>
                            <password>jxfijUIHOInfjnaj</password>
                        </security>
```

### Add postgres JDBC driver
```
                    <drivers>
                        <driver name="postgresql" module="org.postgresql">
                            <xa-datasource-class>org.postgresql.xa.PGXADataSource</xa-datasource-class>
                        </driver>
                        <driver name="h2" module="com.h2database.h2">
                            <xa-datasource-class>org.h2.jdbcx.JdbcDataSource</xa-datasource-class>
                        </driver>
                    </drivers>
```

### Change keycloak server Datasource
```
            <subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
                ...
                <spi name="connectionsJpa">
                 <provider name="default" enabled="true">
                     <properties>
                         <property name="dataSource" value="java:jboss/datasources/KeycloakDS"/>
                         <property name="initializeEmpty" value="false"/>
                         <property name="migrationStrategy" value="manual"/>
                         <property name="migrationExport" value="${jboss.home.dir}/keycloak-database-update.sql"/>
                     </properties>
                 </provider>
                </spi>
                ...
            </subsystem>
```
#### Note:
Postgres DB user Authentication method must be trust.

### Copy JDBC Driver to RH-SSO module
```
$ mkdir -p /opt/rh/sso/server/modules/system/layers/keycloak/org/postgresql/main
$ cp postgresql-9.4.1212.jar /opt/rh/sso/server/modules/system/layers/keycloak/org/postgresql/main/

echo '<?xml version="1.0" ?>
<module xmlns="urn:jboss:module:1.3" name="org.postgresql">

    <resources>
        <resource-root path="postgresql-9.4.1212.jar"/>
    </resources>

    <dependencies>
        <module name="javax.api"/>
        <module name="javax.transaction.api"/>
    </dependencies>
</module>' > /opt/rh/sso/server/modules/system/layers/keycloak/org/postgresql/main/module.xml

```

### Config to Open only HTTPS with TLSv1.2

#### Remove http-listener under subsystem "urn:jboss:domain:undertow:10.0"
```
$ cd /opt/rh/sso/server/bin
$ jboss-cli.sh --connect --controller=localhost:9990
/profile=auth-server-clustered/subsystem=undertow/server=default-server/http-listener=default:remove
```

#### Change https-listener name to "default"
```
                <server name="default-server">
                    <ajp-listener name="ajp" socket-binding="ajp"/>
                    <https-listener name="default" socket-binding="https" ssl-context="httpsSSC" enable-http2="true"/>
```

#### Generate key and keystore and add to config
```
keytool -genkeypair -alias rhsso -keyalg EC -keysize 256 -validity 5475 -keystore /opt/rh/sso/keystore/keystore.jks -dname "CN=rhsso" -keypass Changeit -storepass Changeit
$ cd /opt/rh/sso/server/bin
$ jboss-cli.sh --connect --controller=localhost:9990

/profile=auth-server-clustered/subsystem=elytron/key-store=httpsKS:add(path=/opt/rh/sso/keystore/keystore.jks, credential-reference={clear-text=Changeit}, type=JKS)
/profile=auth-server-clustered/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS, algorithm="PKIX", credential-reference={clear-text=Changeit})
/profile=auth-server-clustered/subsystem=elytron/server-ssl-context=httpsSSC:add(key-manager=httpsKM, protocols=["TLSv1.2"])
batch
/profile=auth-server-clustered/subsystem=undertow/server=default-server/https-listener=default:undefine-attribute(name=security-realm)
/profile=auth-server-clustered/subsystem=undertow/server=default-server/https-listener=default:write-attribute(name=ssl-context, value=httpsSSC)
run-batch
```

#### Remove socket-binding http under socket-binding-group "standard-sockets" and "ha-sockets"
```
/socket-binding-group=standard-sockets/socket-binding=http:remove
/socket-binding-group=ha-sockets/socket-binding=http:remove

OR manual remove
            <!-- <socket-binding name="http" port="${jboss.http.port:8080}"/> -->
```

### Enable Trustore For connect to LDAPS or DB via HTTPS
```
$ jboss-cli.sh --connect --controller=localhost:9990
/profile=auth-server-clustered/subsystem=elytron/trust-manager=default-trust-manager:add(key-store=httpsKS)
/profile=auth-server-clustered/subsystem=core-management/management-interface=http-interface:add()
/profile=auth-server-clustered/core-service=management/management-interface=http-interface:write-attribute(name=ssl-context, value=httpsSSC)
/profile=auth-server-clustered/core-service=management/management-interface=http-interface:write-attribute(name=secure-socket-binding, value=management-https)
```

## Set LDAPS
```
$ openssl s_client -showcerts -connect 192.168.218.22:636
$ vi /opt/rh/sso/keystore/ad.pem
$ openssl x509 -outform der -in /opt/rh/sso/keystore/ad.pem -out /opt/rh/sso/keystore/ad.der
$ keytool -import -alias adrootca -keystore /opt/rh/sso/keystore/keystore.jks -file /opt/rh/sso/keystore/ad.der
```
Add spi trustore in subsystem "urn:jboss:domain:keycloak-server:1.1"
```
                <spi name="truststore">
                    <provider name="file" enabled="true">
                        <properties>
                            <property name="file" value="/opt/rh/sso/keystore/keystore.jks" />
                            <property name="password" value="Changeit" />
                            <property name="hostname-verification-policy" value="WILDCARD"/>
                            <property name="disabled" value="false"/>
                        </properties>
                    </provider>
                </spi>
```

### Change Infinispan Cache from distibute to Replicate to make session replication working properly
```
            <subsystem xmlns="urn:jboss:domain:infinispan:9.0">
                <cache-container name="keycloak">
                    <transport lock-timeout="60000"/>
                    <local-cache name="realms">
                        <object-memory size="10000"/>
                    </local-cache>
                    <local-cache name="users">
                        <object-memory size="10000"/>
                    </local-cache>                    
                    <local-cache name="authorization">
                        <object-memory size="10000"/>
                    </local-cache>
                    <local-cache name="keys">
                        <object-memory size="1000"/>
                        <expiration max-idle="3600000"/>
                    </local-cache>
                    <replicated-cache name="work"/>
                    <replicated-cache name="sessions"/>
                    <replicated-cache name="authenticationSessions"/>
                    <replicated-cache name="offlineSessions"/>
                    <replicated-cache name="clientSessions"/>
                    <replicated-cache name="offlineClientSessions"/>
                    <replicated-cache name="loginFailures"/>
                    <replicated-cache name="actionTokens">
                        <object-memory size="-1"/>
                        <expiration interval="300000" max-idle="-1"/>
                    </replicated-cache>
                </cache-container>
                <cache-container name="server" aliases="singleton cluster" default-cache="default" module="org.wildfly.clustering.server">
                    <transport lock-timeout="60000"/>
                    <replicated-cache name="default">
                        <transaction mode="BATCH"/>
                    </replicated-cache>
                </cache-container>
                <cache-container name="web" default-cache="repl" module="org.wildfly.clustering.web.infinispan">
                    <transport lock-timeout="60000"/>
                    <replicated-cache name="sso">
                        <locking isolation="REPEATABLE_READ"/>
                        <transaction mode="BATCH"/>
                    </replicated-cache>
                    <replicated-cache name="repl">
                        <locking isolation="REPEATABLE_READ"/>
                        <transaction mode="BATCH"/>
                        <file-store/>
                    </replicated-cache>
                    <replicated-cache name="routing"/>
                    <distributed-cache name="concurrent">
                        <file-store/>
                    </distributed-cache>
                </cache-container>
```

### Update jgroup secret to make internal communication in domain more secure
```
            <subsystem xmlns="urn:jboss:domain:jgroups:7.0">
                <channels default="ee">
                    <channel name="ee" stack="udp" cluster="ejb"/>
                </channels>
                <stacks>
                    <stack name="udp">
                        <transport type="UDP" socket-binding="jgroups-udp"/>
                        <protocol type="PING"/>
                        <protocol type="MERGE3"/>
                        <socket-protocol type="FD_SOCK" socket-binding="jgroups-udp-fd"/>
                        <protocol type="FD_ALL"/>
                        <protocol type="VERIFY_SUSPECT"/>
                        <protocol type="org.jgroups.protocols.ASYM_ENCRYPT">
                            <property name="encrypt_entire_message">true</property>
                            <property name="sym_keylength">128</property>
                            <property name="sym_algorithm">AES/ECB/PKCS5Padding</property>
                            <property name="asym_keylength">512</property>
                            <property name="asym_algorithm">RSA</property>
                        </protocol>
                        <protocol type="pbcast.NAKACK2"/>
                        <protocol type="UNICAST3"/>
                        <protocol type="pbcast.STABLE"/>
                        <auth-protocol type="AUTH">
                            <digest-token algorithm="SHA-512">
                                <shared-secret-reference clear-text="m94kASEjkUYTYQTc930bgVDyd1yj2AgG"/>
                            </digest-token>
                        </auth-protocol>
                        <protocol type="pbcast.GMS"/>
                        <protocol type="UFC"/>
                        <protocol type="MFC"/>
                        <protocol type="FRAG3"/>
                    </stack>
                    <stack name="tcp">
                        <transport type="TCP" socket-binding="jgroups-tcp"/>
                        <socket-protocol type="MPING" socket-binding="jgroups-mping"/>
                        <protocol type="MERGE3"/>
                        <socket-protocol type="FD_SOCK" socket-binding="jgroups-tcp-fd"/>
                        <protocol type="FD_ALL"/>
                        <protocol type="VERIFY_SUSPECT"/>
                        <protocol type="org.jgroups.protocols.ASYM_ENCRYPT">
                            <property name="encrypt_entire_message">true</property>
                            <property name="sym_keylength">128</property>
                            <property name="sym_algorithm">AES/ECB/PKCS5Padding</property>
                            <property name="asym_keylength">512</property>
                            <property name="asym_algorithm">RSA</property>
                        </protocol>
                        <protocol type="pbcast.NAKACK2"/>
                        <protocol type="UNICAST3"/>
                        <protocol type="pbcast.STABLE"/>
                        <auth-protocol type="AUTH">
                            <digest-token algorithm="SHA-512">
                                <shared-secret-reference clear-text="m94kASEjkUYTYQTc930bgVDyd1yj2AgG"/>
                            </digest-token>
                        </auth-protocol>
                        <protocol type="pbcast.GMS"/>
                        <protocol type="MFC"/>
                        <protocol type="FRAG3"/>
                    </stack>
                </stacks>
            </subsystem>
```

### Change private interface from loopback IP to etc/hosts hostname
```
    <interfaces>
        <interface name="management"/>
        <interface name="private">
            <inet-address value="${jboss.bind.address.private:rhsso.private}"/>
        </interface>
        <interface name="public"/>
    </interfaces>
```
Also change all /etc/hosts of each node to match it owned IP (if not have dns name)
```
192.168.218.129     rhsso.private
```


## Set SMTP with TLS
### Add SMTP Server certificate to trustore
```
$ openssl s_client -starttls smtp -connect mbixmail.mbix.co.th:587
$ vi /opt/rh/sso/keystore/smtp.pem
$ sudo keytool -import -trustcacerts -alias "mbixsmtp" -file /opt/rh/sso/keystore/smtp.pem -keystore /opt/rh/sso/keystore/keystore.jks
```
### Config Email in webui (Don't forget to add email to admin user).



## Config master-host
### Change Interface Loopback IP, public to certificate CN name and management to master hostname
```
    <interfaces>
        <interface name="management">
            <inet-address value="${jboss.bind.address.management:rhsso.master}"/>
        </interface>
        <interface name="public">
            <inet-address value="${jboss.bind.address:rhsso}"/>
        </interface>
    </interfaces>
```

### Add server name
```
    <servers>
        <server name="mbix-sso01" group="auth-server-group" auto-start="true"/>
    </servers>
```

### Remove server load-balancer
```
$ jboss-cli.sh --connect --controller=localhost:9990
/profile=auth-server-clustered/subsystem=undertow/server=load-balancer:remove

OR manual remove
    <!-- <servers>
        <server name="load-balancer" group="load-balancer-group"/> -->
```

### Remove port-offset
```
            <!-- <socket-bindings port-offset="150"/> -->
```

### Disable jboss management http and enable https
```
ADD management certificate

            <security-realm name="ManagementRealm">
                <server-identities>
                    <ssl>
                        <keystore path="/opt/rh/sso/keystore/keystore.jks" keystore-password="Changeit" alias="rhsso"/>
                    </ssl>
                </server-identities>
                
ADD application certificate

            <security-realm name="ApplicationRealm">
                <server-identities>
                    <ssl>
                        <keystore path="/opt/rh/sso/keystore/appkeystore.jks" keystore-password="Changeit" alias="rhsso"/>
                    </ssl>
                </server-identities>

ADD http secure-port to management interface

        <management-interfaces>
            <native-interface security-realm="ManagementRealm">
                <socket interface="management" port="${jboss.management.native.port:9999}"/>
            </native-interface>
            <http-interface security-realm="ManagementRealm">
                <http-upgrade enabled="true"/>
                <socket interface="management" secure-port="${jboss.management.https.port:9443}"/>
            </http-interface>
        </management-interfaces>

```

### Extract and add cert to java cacerts keystore for cluster secure communication on all sso host
```
keytool -export -alias rhsso -file /opt/rh/sso/7.4/keystore/rhsso.crt -keystore /opt/rh/sso/7.4/keystore/keystore.jks
sudo keytool -import -trustcacerts -alias "rhsso" -file /opt/rh/sso/7.4/keystore/rhsso.crt -keystore /etc/alternatives/jre/lib/security/cacerts
```

## Config master-slave
### Add user to management realm
```
$ add-user.sh
 What type of user do you wish to add?
  a) Management User (mgmt-users.properties)
  b) Application User (application-users.properties)
 (a): a
 Enter the details of the new user to add.
 Using realm 'ManagementRealm' as discovered from the existing property files.
 Username : admin
 Password recommendations are listed below. To modify these restrictions edit the add-user.properties configuration file.
  - The password should not be one of the following restricted values {root, admin, administrator}
  - The password should contain at least 8 characters, 1 alphabetic character(s), 1 digit(s), 1 non-alphanumeric symbol(s)
  - The password should be different from the username
 Password :
 Re-enter Password :
 What groups do you want this user to belong to? (Please enter a comma separated list, or leave blank for none)[ ]:
 About to add user 'admin' for realm 'ManagementRealm'
 Is this correct yes/no? yes
 Added user 'admin' to file '/.../standalone/configuration/mgmt-users.properties'
 Added user 'admin' to file '/.../domain/configuration/mgmt-users.properties'
 Added user 'admin' with groups to file '/.../standalone/configuration/mgmt-groups.properties'
 Added user 'admin' with groups to file '/.../domain/configuration/mgmt-groups.properties'
 Is this new user going to be used for one AS process to connect to another AS process?
 e.g. for a slave host controller connecting to the master or for a Remoting connection for server to server EJB calls.
 yes/no? yes
 To represent the user add the following to the server-identities definition <secret value="UEBzc3cwcmQ=" />
 ```

### Change secret value
```
    <management>
        <security-realms>
            <security-realm name="ManagementRealm">
                <server-identities>
                    <!-- Replace this with either a base64 password of your own, or use a vault with a vault expression -->
                    <secret value="UEBzc3cwcmQ="/>
```

### Change domain controller user and master address
```
    <domain-controller>
        <remote username="admin" security-realm="ManagementRealm">
            <discovery-options>
                <static-discovery name="primary" protocol="${jboss.domain.master.protocol:remote}" host="${jboss.domain.master.address:rhsso.master}" port="${jboss.domain.master.port:9999}"/>
            </discovery-options>
```

### Change Interface address to certificate CN or hostname in /etc/host
```
    <interfaces>
        <interface name="management">
            <inet-address value="${jboss.bind.address.management:rhsso}"/>
        </interface>
        <interface name="public">
            <inet-address value="${jboss.bind.address:rhsso}"/>
        </interface>
```
Also change all /etc/hosts of each node to match it owned IP
```
192.168.218.130     rhsso
```

### Change Server name
```
    <servers>
        <server name="server01" group="auth-server-group" auto-start="true">
```
Also Remove port-offset
```
            <!-- <socket-bindings port-offset="250"/> -->
```



## Config sso node to start as service
### edit /opt/rh/sso/server/bin/init.d/jboss-eap.conf
For master node
```
# General configuration for the init.d scripts,
# not necessarily for JBoss EAP itself.
# default location: /etc/default/jboss-eap

## Location of JDK
JAVA_HOME="/usr"

## Location of JBoss EAP
JBOSS_HOME="/opt/rh/sso/server"

## The username who should own the process.
JBOSS_USER=rhsso

## The mode JBoss EAP should start, standalone or domain
JBOSS_MODE=domain

## Configuration for standalone mode
# JBOSS_CONFIG=standalone.xml

## Configuration for domain mode
JBOSS_DOMAIN_CONFIG=domain.xml
JBOSS_HOST_CONFIG=host-master.xml

## The amount of time to wait for startup
STARTUP_WAIT=60

## The amount of time to wait for shutdown
SHUTDOWN_WAIT=60

## Location to keep the console log
JBOSS_CONSOLE_LOG="/var/log/rhsso/console.log"

## Additionals args to include in startup
# JBOSS_OPTS="--admin-only -b 127.0.0.1"
```

For slave node
```
# General configuration for the init.d scripts,
# not necessarily for JBoss EAP itself.
# default location: /etc/default/jboss-eap

## Location of JDK
JAVA_HOME="/usr"

## Location of JBoss EAP
JBOSS_HOME="/opt/rh/sso/server"

## The username who should own the process.
JBOSS_USER=rhsso

## The mode JBoss EAP should start, standalone or domain
JBOSS_MODE=domain

## Configuration for standalone mode
# JBOSS_CONFIG=standalone.xml

## Configuration for domain mode
JBOSS_DOMAIN_CONFIG=domain.xml
JBOSS_HOST_CONFIG=host-slave.xml

## The amount of time to wait for startup
STARTUP_WAIT=60

## The amount of time to wait for shutdown
SHUTDOWN_WAIT=60

## Location to keep the console log
JBOSS_CONSOLE_LOG="/var/log/rhsso/console.log"

## Additionals args to include in startup
# JBOSS_OPTS="--admin-only -b 127.0.0.1"
```

### Copy config and script then create service
```
$ sudo cp /opt/rh/sso/server/bin/init.d/jboss-eap.conf /etc/default/
$ sudo cp /opt/rh/sso/server/bin/init.d/jboss-eap-rhel.sh /etc/init.d/
$ sudo chmod +x /etc/init.d/jboss-eap-rhel.sh
$ sudo chkconfig --add jboss-eap-rhel.sh
```

### Set auto start
```
$ sudo chkconfig jboss-eap-rhel.sh on
$ sudo restorecon -vR /etc/init.d/jboss-eap-rhel.sh
```

### Add keycloak master local admin user
```
$ mkdir /opt/rh/sso/server/domain/servers/mbix-sso01/configuration
$ add-user-keycloak.sh -r master --sc /opt/rh/sso/server/domain/servers/mbix-sso01/configuration -u admin
```
