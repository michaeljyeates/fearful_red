# Fearful Red

## Dependencies

Install the required dependencies (Ubuntu/Debian)

    sudo apt-get install libssl-dev openssl python3-pip

Install the pip dependencies

    pip3 install pymongo ethereum eth-utils

## Running

Edit the variables at the top of server.py if necessary

Run the server

    ./server.py

optionally you can add the port (default is 8000)

    ./server.py 8001

## Testing

Visit http://[server_ip]:8000/poll to see example data which should be posted to the /poll endpoint.  This form will verify the signature.

## Using the API

First create a massage to be signed, this is in http format.  There are 3 keys which must be set:

* **poll_id** : The ID of the poll being completed
* **addr** : The ethereum public key
* **resp** : The ID of the response (integer)

eg.
poll_id=5aad5841d2e09421d308e59c&addr=0xda698365f18079eb148debcd007bafd940ac54e5&resp=1

Then make an HTTP POST request to /poll with the following data

* **msg** = The message generated earlier
* **sig** = The signature provided by the client (either MetaMask or manually via MEW)

JSON data will be returned with the following object

* **success** = boolean indicating a successful signature validation and vote registration
* **error** = If success is false then this will contain a human readable error message

---

## Mongo DB Setup

Poll questions need to be manually loaded at the moment, to create a poll use the following command

    mongo > db.poll.save({text:"This is a good question?", choices:["No","Yes"], active:true})

## Wallet setup

Download the relevant wallet csv file from here [https://github.com/eosdac/airdrop](https://github.com/eosdac/airdrop) and name it wallet.csv

PLEASE NOTE : The wallet file must be later than snapshot 275

Place it in the same folder as server.py, then run the server and load the /setup page.  This will load all of the token balances into the database
