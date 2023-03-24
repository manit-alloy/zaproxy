

#### Steps for running access control scans

1. Build docker image
`docker build -f Dockerfile-weekly -t owasp/zap2docker-weekly:access_control .`

2. Run a sample access control scan 
`docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-weekly:access_control zap-accesscontrol-scan.py -d -t http://host.docker.internal:8000/ -n access_control_testing_0.1.context -r ac_scan_report.html -U Nonadmin_user`
