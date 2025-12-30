#!/bin/sh

set -e

DOMAIN=overnet.ca
ORG=Overnet

rm -rf ca
mkdir -p ca/certs
echo "01" > ca/serial
touch ca/index.txt

# Create self-signed root certificate
openssl req -x509 -nodes -config mdrd_ssl.cnf -newkey ed25519 \
	-keyout ca/key.pem \
	-out ca/root.pem -outform PEM -days 3650 \
	-extensions root_ext \
	-subj "/emailAddress=cert@$DOMAIN/O=$ORG/CN=$ORG CA"

# Create a "client1" cert request
rm -f client1/*
mkdir -p client1
openssl req -nodes -config mdrd_ssl.cnf -newkey ed25519 \
	-keyout client1/key.pem -keyform PEM \
	-out client1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=client1.$DOMAIN" \
	-addext "subjectAltName = DNS:client1.$DOMAIN"

# Sign client1 cert & verify
yes | openssl ca -config mdrd_ssl.cnf -in client1/req.pem -out client1/cert.pem
openssl verify -CAfile ca/root.pem client1/cert.pem

# Create a "client2" cert request
rm -f client2/*
mkdir -p client2
openssl req -nodes -config mdrd_ssl.cnf -newkey ed25519 \
	-keyout client2/key.pem -keyform PEM \
	-out client2/req.pem -outform PEM \
	-subj "/O=$ORG/CN=client2.$DOMAIN" \
	-addext "subjectAltName = DNS:client2.$DOMAIN"

# Sign and revoke client2 cert
yes | openssl ca -config mdrd_ssl.cnf -in client2/req.pem -out client2/cert.pem
openssl verify -CAfile ca/root.pem client2/cert.pem
openssl ca -config mdrd_ssl.cnf -revoke client2/cert.pem

# Generate CRL
openssl ca -config mdrd_ssl.cnf -gencrl -out ca/root.crl
openssl verify -CAfile ca/root.pem -CRLfile ca/root.crl \
	-crl_check client2/cert.pem || true

# View it and verify signature
openssl crl -in ca/root.crl -text -noout -CAfile ca/root.pem

echo "All good!"
