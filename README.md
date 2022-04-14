# scan-report

## Example

### Run with binary
`./scanreport -action=summary -report-type=snyk -path="./fixtures/js-snyk.json"`

### Run with docker image

`docker run --rm -v $PWD/fixtures:/data oscarzhou/scan-report:0.1.0 -action=summary -report-type=snyk -path="/data/js-snyk.json"`

### Debug with ls command

`docker run --rm -v $PWD/fixtures:/data oscarzhou/scan-report:0.1.0 -action=ls -path=/data`