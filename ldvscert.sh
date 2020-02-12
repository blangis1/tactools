#!/bin/bash
pass=$(grep "Passphrase*" /shoretel/etc/ShoreTel.cfg)
if [[ $pass =~ "Passphrase" ]]
then
	echo "Passphrase looks good. Checking certificates.."
else 
	echo "LDVS does not have a passphrase set, as such, it will not receive certificates from HQ" && echo "go to https://oneview.mitel.com/s/article/Troubleshooting-Certificate-Installation-on-LDVS for instructions on how to resolve this."
fi

issuer=$(openssl x509 -noout -in /cf/shorelinedata/keystore/certs/server.crt -issuer)
if [[ $issuer =~ "OU=UC Headquarters/CN=ShoreTel" ]]
then
	echo "Keystore certificate is ShoreTel signed. If you are installing third party certificates, the certificate has not updated"
else 
	echo "server.crt is a third party certificate issued by" && echo  $issuer
fi

certdate=$(find /cf/shorelinedata/keystore/certs -mmin -30)
if [[ $certdate =~ "server.crt" ]]
then
	echo "Server.crt has recently been modified. That's a good sign!"
else
	echo "server.crt has not been updated recently"
fi

keystorecert=$(openssl x509 -noout -in /cf/shorelinedata/keystore/certs/server.crt -fingerprint)
nginxcert=$(openssl x509 -noout -in /etc/nginx/nginx.crt -fingerprint)

if [[ $keystorecert == $nginxcert ]]
then
	echo "keystore certificate matches nginx certificate, CAS should work."
else
	echo "Keystore certificate doesn not match the nginx certificate, CAS may fail."
fi


