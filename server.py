#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import parse_qs
from ethereum.utils import ecrecover_to_pub, sha3, checksum_encode
from eth_utils import encode_hex, decode_hex, add_0x_prefix
from pymongo import MongoClient, InsertOne
from pymongo.errors import BulkWriteError
from bson.objectid import ObjectId
from bson.errors import InvalidId
import csv
import base64
import json

SERVER_LISTEN = '' # blank for all interfaces
MONGO_CONNECTION = 'mongodb://localhost:27017/'
WALLET_FILE = 'wallet.csv'
DB_NAME = 'fearful'


class FearfulServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)


class FearfulHandler(BaseHTTPRequestHandler):
    def __init__(self, a, b, c):
        self.server_version = 'FearfulRed/1.0'
        super().__init__(a, b, c)

    def _set_headers(self, content_type='application/json'):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', content_type)
        self.end_headers()

    def _show_error(self, code, content_type='application/json'):
        self.send_response(code)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', content_type)
        self.end_headers()
        if code == 400:
            msg = 'Invalid parameters'
        elif code == 404:
            msg = 'Page not found'
        else:
            msg = 'Internal Server Error'

        json = '{"success":false, "error":"' + msg + '", "http_code":'+str(code)+'}'

        self.wfile.write(json.encode())


    """
    Returns True if the signature is valid and signed by the signer parameter, False if there is any error
    """
    def _sig_valid(self, signature, message_hash, signer):
        try:
            r = int(signature[0:66], 16)
            s = int(add_0x_prefix(signature[66:130]), 16)
            v = int(add_0x_prefix(signature[130:132]), 16)
            if v not in (27,28):
                v += 27

            pubkey = ecrecover_to_pub(decode_hex(message_hash), v, r, s)

            msg_signer = encode_hex(sha3(pubkey)[-20:])

            valid = (msg_signer == signer.lower())
        except:
            print('exception in _sig_valid')
            valid = False

        return valid

    """
    Returns a connection to the mongo database
    """
    def _mongo_db(self):
        client = MongoClient(MONGO_CONNECTION)

        return client[DB_NAME]

    """
    Imports balances from the 'wallet' export file.  This file should be a csv file with ethereum address and balance.
    Each balance should have 4 decimal places
    """
    def import_balances(self):
        filename = WALLET_FILE
        db = self._mongo_db()
        collection = db.token_balance

        if collection.count() > 0:
            return

        requests = []

        with open(filename, "r") as f:
            reader = csv.reader(f, delimiter=",")
            for i, line in enumerate(reader):
                requests.append(
                    InsertOne({"address":line[0].lower(), "balance":int(line[2].replace('.', ''))})
                )
        try:
            collection.bulk_write(requests)
            collection.create_index('address')
        except BulkWriteError as bwe:
            print(bwe.details)


    """
    Returns the number of tokens owned by the address in our snapshot, returns 0 if the address is not in the snapshot
    """
    def _number_tokens(self, address):
        db = self._mongo_db()
        collection = db.token_balance

        res = collection.find_one({"address":address.lower()})

        if res == None:
            print("No record for %s" % address.lower())
            return 0

        return int(res['balance'])



    """
    Stores a single poll response in the database
    If the address has no tokens then will not enter anything
    """
    def _store_response(self, vote_data):
        db = self._mongo_db()
        collection = db.poll_response

        number_tokens = self._number_tokens(vote_data['address'])

        try:
            poll_id = ObjectId(vote_data['poll_id'])
        except InvalidId:
            return False

        vote_data['larimers'] = number_tokens
        vote_data['poll_id'] = poll_id
        vote_data['response'] = int(vote_data['response'])

        res = collection.update_one({
            'address':vote_data['address'],
            'poll_id':vote_data['poll_id']
        }, {'$set':vote_data}, True)

        return res.acknowledged

    def do_GET(self):
        path_arr = self.path.split('?')
        if path_arr[0] == "/poll":
            # Show the poll form for testing purposes
            self._set_headers(content_type='text/html')
            html = open("poll_form.html").read()
            self.wfile.write(html.encode())


        elif path_arr[0] == "/poll/active":
            # Lists all active polls
            db = self._mongo_db()
            collection = db.poll
            polls = []

            for poll in collection.find({"active":True}):
                poll['_id'] = str(poll['_id'])
                polls.append(poll)

            self._set_headers(content_type='application/json')
            self.wfile.write(json.dumps(polls).encode('utf-8'))

        elif path_arr[0] == "/poll/get":
            db = self._mongo_db()
            collection = db.poll

            get_data = parse_qs(path_arr[1])
            poll = collection.find_one({"_id": ObjectId(get_data['id'][0])})

            if poll is not None:
                poll['_id'] = str(poll['_id'])
                self._set_headers(content_type='application/json')
                self.wfile.write(json.dumps(poll).encode('utf-8'))

        elif path_arr[0] == "/poll/response":
            # gets a vote for a poll and address
            db = self._mongo_db()
            collection = db.poll_response

            get_data = parse_qs(path_arr[1])
            print(get_data)
            resp = collection.find_one({
                'address': get_data['address'][0],
                'poll_id': ObjectId(get_data['poll_id'][0])
            })

            self._set_headers(content_type='application/json')
            if resp is not None:
                resp['_id'] = str(resp['_id'])
                resp['poll_id'] = str(resp['poll_id'])

                self.wfile.write(json.dumps(resp).encode('utf-8'))
            else:
                self.wfile.write(json.dumps(None).encode('utf-8'))

        elif path_arr[0] == "/setup":
            # Import all of the token balances, this will not do anything if token balances are already imported
            self.import_balances()
        else:
            self._show_error(404)

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        try:
            if self.path == "/poll":
                content_length = int(self.headers['Content-Length'])
                length = int(content_length) if content_length else 0

                data = self.rfile.read(length)
                post_data = parse_qs(data)
                print(post_data)


                try:
                    # Calculate the msg_hash from the msg to verify
                    msg = post_data[b'msg'][0]
                    msg_len = len(msg)
                    calc_hash = encode_hex(sha3('\u0019Ethereum Signed Message:\n' + str(msg_len) + msg.decode('ascii')))

                    if post_data[b'sig'] == None or post_data[b'msg'] == None:
                        print('Message or signature missing')
                        self._show_error(400)
                    else:
                        poll_data = parse_qs(msg)
                        address = post_data[b'address'][0].decode("ascii")

                        valid = self._sig_valid(
                            post_data[b'sig'][0].decode("ascii"),
                            calc_hash,
                            address
                        )

                        number_tokens = self._number_tokens(address)

                        self._set_headers(content_type='application/json')

                        if valid and number_tokens:
                            vote_data = {
                                "address": address,
                                "poll_id": poll_data[b'poll_id'][0].decode("ascii"),
                                "response": poll_data[b'resp'][0].decode("ascii")
                            }
                            res = self._store_response(vote_data)

                            if res == True:
                                json = '{"success":true}'
                                self.wfile.write(json.encode())
                            else:
                                msg = 'Failed to register vote, please try later'
                                json = '{"success":false, "error":"'+msg+'"}'
                                self.wfile.write(json.encode())
                        elif not number_tokens:
                            json = '{"success":false, "error":"Address does not have any EOS tokens in our snapshot"}'
                            self.wfile.write(json.encode())
                        else:
                            json = '{"success":false, "error":"Signature invalid"}'
                            self.wfile.write(json.encode())

                except KeyError as e:
                    print(e)
                    self._show_error(400)

            else:
                self._show_error(404)

        except Exception as e:
            self._show_error(500)
            print('exception', e)
            raise e


def run(server_class=FearfulServer, handler_class=FearfulHandler, port=8000):
    server_address = (SERVER_LISTEN, port)
    httpd = server_class(server_address, handler_class)
    print('Starting Fearful Red on port '+str(port)+'...')
    httpd.serve_forever()


if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()