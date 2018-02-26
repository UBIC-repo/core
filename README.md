Installation
===
```
sudo apt-get update
sudo apt-get install git cmake gcc make libleveldb1v5 libpcsclite1 libpcsclite-dev libleveldb-dev libboost-all-dev gcc g++ ntp
```


Use ntp
===
```
sudo service ntp stop
sudo apt-get install ntpdate  
sudo ntpdate pool.ntp.org
sudo service ntp start
```

Install OpenSSL 1.1
===
```
cd /usr/local/src
sudo wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz && sudo tar xzvf openssl-1.1.0g.tar.gz && cd openssl-1.1.0g
sudo ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
sudo make
sudo make install

openssl version # make sure it is version 1.1
```

Install UBIC
===
```
cd /usr/local/src
sudo git clone https://github.com/UBIC-repo/core.git
sudo chmod 777 -R core
cd core
cmake CMakeLists.txt
make
sudo make install
```

Run the server
===
```
/etc/init.d/ubic start
```

Stop the server
===
```
/etc/init.d/ubic stop
```

Open the web interface
===
To open the web interface you have to open 127.0.0.1:6789/#yourApiKey in your browser.

You will find your api key in the ```~/ubic/config.ini``` file.

/!\ Warning: For security reasons the web interface can not be opened remotly by typing your server ip:6789/#yourApiKey.
If you want to open the web insterface of your sever do a port forwarding over SSH, and forward the ports 6789 and 12303 to the ports 6789 and 12303 on your local machine.

Register a passport
===
To register a passport go to the "My UBI" tab and click "Register passport", then enter your passport number, date of birth and the date of expiry.
Make sure your NFC reader is plugged and ready, put the passport on top of it. To help you on some readers a green light appears when it found a tag.
Click "Register passport", if it doesnt work try again by turning your passport, opening it. If it still doesn't work open an issue on Github.

Note that to work your node should ideally be synced.
