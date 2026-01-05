# oidc-prac
## Run Test
```bash
cd conformance-suite
docker compose -f docker-compose-localtest.yml up -d
```
- 証明書の追加
```bash
docker compose -f docker-compose-localtest.yml exec -it httpd cat /etc/ssl/certs/ssl-cert-snakeoil.pem > ~/Downloads/localhost-cert.pem
docker exec -it conformance-suite-httpd-1 cat /etc/ssl/certs/ssl-cert-snakeoil.pem > ~/Downloads/localhost-cert.pem
sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain ~/Downloads/localhost-cert.pem
```
- 削除
```bash
openssl x509 -fingerprint -sha256 -in ~/Downloads/localhost-cert.pem | grep "sha" | grep -o -E "[0-9A-Z:]{64}" | sed "s/://g"
sudo security delete-certificate -c localhost -Z "<SHA256_HASH>" /Library/Keychains/System.keychain
```
- https://localhost:8443/
