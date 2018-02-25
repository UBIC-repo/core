if [ ! -d "/var/ubic/" ]; then
	mkdir /var/ubic/
fi

chmod 777 /var/ubic/

cp -R ./Static/web /var/ubic/
cp -R ./Static/genesis/certs /var/ubic/
cp -R ./Static/genesis/x509 /var/ubic/
cp -R ./Static/genesis/votes.mdb /var/ubic/

chmod 777 -R /var/ubic/

cp ./ubicd /usr/bin/
cp ./Static/init.d/ubic /etc/init.d/
