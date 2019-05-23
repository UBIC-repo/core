echo "Running install.sh"
cp ./ubicd /usr/bin/
cp ./ubic /usr/bin/
cp ./Static/init.d/ubic /etc/init.d/

if [ ! -d "/var/ubic/" ]; then
	mkdir /var/ubic/
else
	cp -R ./Static/web /var/ubic/
	cp -R ./Static/genesis /var/ubic/genesis
	exit 1
fi

chmod 777 /var/ubic/

cp -R ./Static/web /var/ubic/
cp -R ./Static/genesis/certs /var/ubic/
cp -R ./Static/genesis/x509 /var/ubic/
cp -R ./Static/genesis/votes.mdb /var/ubic/
cp -R ./Static/genesis /var/ubic/genesis

chmod 777 -R /var/ubic/
