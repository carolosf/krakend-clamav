# Need to put some of these in docker compose for easier testing
quick_build_docker:
	docker buildx build --platform linux/amd64 -f Dockerfile.quickbuild -t quickbuild .

quick_build:
	docker run --rm --name krakend-clamav-quick-build --rm -it -v "${PWD}:/app" --platform linux/amd64 -e CGO_ENABLED=1 -e GOOS=linux -e GOARCH=amd64 -w /app quickbuild sh -c "go build -buildmode=plugin -o plugins/yourplugin.so ."

quick_run:
	docker run --rm --name krakend-clamav-quick-run --platform linux/amd64 -p "8080:8080" -v "${PWD}:/etc/krakend/" -v "${PWD}/plugins:/opt/krakend/plugins/" devopsfaith/krakend run -c /etc/krakend/krakend.json

quick_run_response:
	docker run --rm --name krakend-clamav-quick-run-response --platform linux/amd64 -p "8083:8080" -v "${PWD}:/etc/krakend/" -v "${PWD}/plugins:/opt/krakend/plugins/" devopsfaith/krakend run -c /etc/krakend/krakend2.json

quick_build_and_run: quick_build quick_run

run_clamav:
	docker run --rm --name test-clamav -d -p 3310:3310 mkodockx/docker-clamav:alpine

run_nginx:
	docker run --rm --name test-nginx -d -p 8081:80 nginx

run_nginx_response:
	docker run --rm --name test-nginx-response -p 8082:80 -v "${PWD}/docker-nginx-response/static:/usr/share/nginx/html:ro" -d nginx

curl_form:
	curl -X POST -F key1=value1 -F 'upload=@"${PWD}/docker-nginx-response/static/eicar.com.txt"' -v http://localhost:8080/

curl_download_eicar:
	curl http://localhost:8080/eicar.com.txt