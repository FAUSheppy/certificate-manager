# OpenVPN CCD-Integration
Create a client-config-dir for your server by adding the `client-config-dir /path/to/ccd/from/cert-manager` and and `ccd-exclusive' options to your openvpn-server configuration.

This will allow you to use the generated client config from the certificate manager in OpenVPN to assign static IPs and prevent logins from unauthenticated users - even if they have a valid certificate otherwise.

The configs should look like this:

    ifconfig-push 172.16.1.10 255.255.255.0
    ifconfig-ipv6-push fd2a:aef:608:1::1010/64

If you want these config to adhere to the rules laid out in the web interface, you will have to add the appropriate *netfilter*-rules though, for example:

    iptables -A FORWARD -s 172.16.1.1/32 -i NAME_OF_YOUR_VPN_DEVICE -j ACCEPT
    iptables -A FORWARD -s 172.16.1.0/29 -i NAME_OF_YOUR_VPN_DEVICE -j ACCEPT
    iptables -A FORWARD -s 172.16.1.20/29 -d 172.16.1.0/24 -i NAME_OF_YOUR_VPN_DEVICE -j DROP

Also make sure that you have forwarding enabled:

    sysctl -a | grep forward

# OpenVPN Management Interface
If you want to use the **experimental** integration of the OpenVPN management interface, enable the interface by adding `management 127.0.0.1 23000 pass.txt` to your OpenVPN-server configuration and add a file `pass.txt` in the OpenVPN-root directory with a single line and **no** newline containing a password.

Configure the password and server settings in the certificate-manager via the app.config-VPN\* variables.

# Parsing Nginx Maps
You can put a Nginx config file containing maps here (or link to it).

    map $ssl_client_s_dn $allow_group_main {
        default "";
        ~CN=Sheppy true;
        ~CN=Kathi true;
    }
    
    map $ssl_client_s_dn $allow_group_ths {
        default "";
        ~OU=THS true;
    }

..to display information about permission in the `/cert-info` location.

With this map you can set headers in Nginx to be used for authentication later. For example like this:

    proxy_set_header X-Nginx-Cert-Auth $allow_group_main

.. and use them in other applications or also in Nginx itself to for example bypass basic auth:

    map $http_x_nginx_cert_auth $basic_auth_val {
        default "private";
        true off;
    }

    location /auth/{
        auth_basic $basic_auth_val;
        auth_basic_user_file /etc/nginx/htpasswd;
    }

# Using the CRL (Certificate Revocation List)
For Nginx the CRL option is:

    ssl_crl /path/to/crl/file.pem

For OpenVPN it is

    crl-verify /path/to/crl/file.pem

Neither of these services need to be reloaded, but the CRL will only be checked for new connections.
If you have configured the OpenVPN-Management integration the clients will automatically be disconnected if their certificate is revoked via the interface (but not if you revoke the certificate manually).
