module github.com/siemens/GoScans

go 1.24.0

toolchain go1.24.7

// Negative serial numbers are note allowed according to RFC 5280. However, sometimes such certificates
// can be encountered in the wild. Valid or not, in this package we still want to parse such certificates
// to extract their contents.
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
// https://github.com/microsoft/mssql-docker/issues/895#issuecomment-2327988940
godebug x509negativeserial=1

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358
	github.com/PuerkitoBio/goquery v1.10.3
	github.com/Ullaakut/nmap/v3 v3.0.6
	github.com/cockroachdb/apd v1.1.0
	github.com/davecgh/go-spew v1.1.1
	github.com/gabriel-vasile/mimetype v1.4.10
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/go-ole/go-ole v1.3.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/krp2/go-nfs-client v0.0.0-20200713104628-eb4e3e9b6e95
	github.com/mattn/go-adodb v0.0.2-0.20200211113401-5e535a33399b
	github.com/neo4j/neo4j-go-driver/v5 v5.28.3
	github.com/noneymous/GoSslyze v0.0.0-20250611082550-d3ca74beb1c0
	github.com/noneymous/go-redistributable-checker v0.0.0-20210325125326-f5f65eef4761
	github.com/orcaman/concurrent-map/v2 v2.0.1
	github.com/vmware/go-nfs-client v0.0.0-20190605212624-d43b92724c1b
	github.com/ziutek/telnet v0.1.0
	golang.org/x/crypto v0.41.0
	golang.org/x/net v0.43.0
	golang.org/x/sys v0.36.0
)

require (
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-resty/resty/v2 v2.16.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rasky/go-xdr v0.0.0-20170124162913-1a41d1a06c93 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)
