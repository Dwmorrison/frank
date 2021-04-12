import sys
import platform
import time
import base64
import hashlib
import hmac
import json #added this to parse the json string in to dics of dics

if int(platform.python_version_tuple()[0]) > 2:
	import urllib.request as urllib2
else:
	import urllib2
api_public = {"Time", "Assets", "AssetPairs", "Ticker", "OHLC", "Depth", "Trades", "Spread"}
api_private = {"Balance", "TradeBalance", "OpenOrders", "ClosedOrders", "QueryOrders", "TradesHistory", "QueryTrades", "OpenPositions", "Ledgers", "QueryLedgers", "TradeVolume", "AddExport", "ExportStatus", "RetrieveExport", "RemoveExport", "GetWebSocketsToken"}
api_trading = {"AddOrder", "CancelOrder"}
api_funding = {"DepositMethods", "DepositAddresses", "DepositStatus", "WithdrawInfo", "Withdraw", "WithdrawStatus", "WithdrawCancel", "WalletTransfer"}

api_domain = "https://api.kraken.com"
base = 'XBT'
asset = 'PAXG'
assetpair = f'{asset}{base}'
base_asset_percentage = 90
speed = 25

def timer(x):
	start_time = int(time.time()*10)
	seconds = x
	while True:
		now = int(time.time()*10)
		elapsed_time = now - start_time
		if elapsed_time == seconds:
			start_time = int(time.time()*10)
			return True

def ordermin(assetpair):
	
	api_data = ""
	api_method = 'AssetPairs'
	api_data = "pair=PAXGXBT"

	if api_method in api_private or api_method in api_trading or api_method in api_funding:
		api_path = "/0/private/"
		api_nonce = str(int(time.time()*1000))
		try:
			api_key = open("Penis.txt").read().strip()
			api_secret = base64.b64decode(open("Vagina.txt").read().strip())
		except:
			print("API public key and API private (secret) key must be in text files called API_Public_Key and API_Private_Key")
			sys.exit(1)
		api_postdata = api_data + "&nonce=" + api_nonce
		api_postdata = api_postdata.encode('utf-8')
		api_sha256 = hashlib.sha256(api_nonce.encode('utf-8') + api_postdata).digest()
		api_hmacsha512 = hmac.new(api_secret, api_path.encode('utf-8') + api_method.encode('utf-8') + api_sha256, hashlib.sha512)
		api_request = urllib2.Request(api_domain + api_path + api_method, api_postdata)
		api_request.add_header("API-Key", api_key)
		api_request.add_header("API-Sign", base64.b64encode(api_hmacsha512.digest()))
		api_request.add_header("User-Agent", "Kraken REST API")
	elif api_method in api_public:
		api_path = "/0/public/"
		api_request = urllib2.Request(api_domain + api_path + api_method + '?' + api_data)
		api_request.add_header("User-Agent", "Kraken REST API")
		
	else:
		print("Usage: %s method [parameters]" % sys.argv[0])
		print("Example: %s OHLC pair=xbtusd interval=1440" % sys.argv[0])
		sys.exit(1)

	try:
		api_reply = urllib2.urlopen(api_request).read()
	except Exception as error:
		print("API call failed (%s)" % error)
		sys.exit(1)

	try:
		api_reply = api_reply.decode()
	except Exception as error:
		if api_method == 'RetrieveExport':
			sys.stdout.buffer.write(api_reply)
			sys.exit(0)
		print("API response invalid (%s)" % error)
		sys.exit(1)

	if '"error":[]' in api_reply:
		pass
		
	else:
		print(api_reply)
		print(api_domain + api_path + api_method + '?' + api_data)
		sys.exit(1)

	
	MRP = json.loads(api_reply)
	MRP = MRP['result']
	MRP = MRP[f'{assetpair}']
	MRP = float(MRP['ordermin'])
	# MRP = MRP[0]
	
	return MRP

def Balance(base,asset,assetpair):
	base = f'X{base}'
	api_data = ""
	api_method = 'Balance'
	api_data = ""

	if api_method in api_private or api_method in api_trading or api_method in api_funding:
		api_path = "/0/private/"
		api_nonce = str(int(time.time()*1000))
		try:
			api_key = open("Penis.txt").read().strip()
			api_secret = base64.b64decode(open("Vagina.txt").read().strip())
		except:
			print("API public key and API private (secret) key must be in text files called API_Public_Key and API_Private_Key")
			sys.exit(1)
		api_postdata = api_data + "&nonce=" + api_nonce
		api_postdata = api_postdata.encode('utf-8')
		api_sha256 = hashlib.sha256(api_nonce.encode('utf-8') + api_postdata).digest()
		api_hmacsha512 = hmac.new(api_secret, api_path.encode('utf-8') + api_method.encode('utf-8') + api_sha256, hashlib.sha512)
		api_request = urllib2.Request(api_domain + api_path + api_method, api_postdata)
		api_request.add_header("API-Key", api_key)
		api_request.add_header("API-Sign", base64.b64encode(api_hmacsha512.digest()))
		api_request.add_header("User-Agent", "Kraken REST API")
	elif api_method in api_public:
		api_path = "/0/public/"
		api_request = urllib2.Request(api_domain + api_path + api_method + '?' + api_data)
		api_request.add_header("User-Agent", "Kraken REST API")
		
	else:
		print("Usage: %s method [parameters]" % sys.argv[0])
		print("Example: %s OHLC pair=xbtusd interval=1440" % sys.argv[0])
		sys.exit(1)

	try:
		api_reply = urllib2.urlopen(api_request).read()
	except Exception as error:
		print("API call failed (%s)" % error)
		sys.exit(1)

	try:
		api_reply = api_reply.decode()
	except Exception as error:
		if api_method == 'RetrieveExport':
			sys.stdout.buffer.write(api_reply)
			sys.exit(0)
		print("API response invalid (%s)" % error)
		sys.exit(1)

	if '"error":[]' in api_reply:
		pass
		
	else:
		print(api_reply)
		print(api_domain + api_path + api_method + '?' + api_data)
		sys.exit(1)

	# equilibrium = api_reply
	
	MRP = json.loads(api_reply)
	MRP = MRP['result']
	base = MRP[base]
	asset = MRP[asset]
	# print(MRP[0])
	# print( time.asctime( time.localtime(time.time()) ))
	return base, asset

def Ticker(assetpair):
	
	api_data = ""
	api_method = 'Ticker'
	api_data = f"pair={assetpair}"

	if api_method in api_private or api_method in api_trading or api_method in api_funding:
		api_path = "/0/private/"
		api_nonce = str(int(time.time()*1000))
		try:
			api_key = open("Penis.txt").read().strip()
			api_secret = base64.b64decode(open("Vagina.txt").read().strip())
		except:
			print("API public key and API private (secret) key must be in text files called API_Public_Key and API_Private_Key")
			sys.exit(1)
		api_postdata = api_data + "&nonce=" + api_nonce
		api_postdata = api_postdata.encode('utf-8')
		api_sha256 = hashlib.sha256(api_nonce.encode('utf-8') + api_postdata).digest()
		api_hmacsha512 = hmac.new(api_secret, api_path.encode('utf-8') + api_method.encode('utf-8') + api_sha256, hashlib.sha512)
		api_request = urllib2.Request(api_domain + api_path + api_method, api_postdata)
		api_request.add_header("API-Key", api_key)
		api_request.add_header("API-Sign", base64.b64encode(api_hmacsha512.digest()))
		api_request.add_header("User-Agent", "Kraken REST API")
	elif api_method in api_public:
		api_path = "/0/public/"
		api_request = urllib2.Request(api_domain + api_path + api_method + '?' + api_data)
		api_request.add_header("User-Agent", "Kraken REST API")
		
	else:
		print("Usage: %s method [parameters]" % sys.argv[0])
		print("Example: %s OHLC pair=xbtusd interval=1440" % sys.argv[0])
		sys.exit(1)

	try:
		api_reply = urllib2.urlopen(api_request).read()
	except Exception as error:
		print("API call failed (%s)" % error)
		sys.exit(1)

	try:
		api_reply = api_reply.decode()
	except Exception as error:
		if api_method == 'RetrieveExport':
			sys.stdout.buffer.write(api_reply)
			sys.exit(0)
		print("API response invalid (%s)" % error)
		sys.exit(1)

	if '"error":[]' in api_reply:
		pass
		
	else:
		print(api_reply)
		print(api_domain + api_path + api_method + '?' + api_data)
		sys.exit(1)

	# equilibrium = api_reply
	
	MRP = json.loads(api_reply)
	MRP = MRP['result']
	MRP = MRP[f'{assetpair}']
	MRP = MRP['c']
	MRP = MRP[0]
	# print( time.asctime( time.localtime(time.time()) ))
	return MRP

def Gap(equity, base_asset_percentage, asset_value_in_base_terms):
	base_asset_percentage = float(base_asset_percentage/100)
	target = float("{:.8f}".format(equity * base_asset_percentage))
	gap = float("{:.8f}".format(asset_value_in_base_terms - target))
	return gap

def hold(gap, assetpair):
	gap = abs(gap)
	if gap < ordermin(assetpair):
		hold = True
	else:
		hold = False
	return hold




mins = 0
counter = 0
orders = 0
x = ordermin(assetpair)
while True:
    if timer(speed):
        counter += 1
        balances = Balance(base,asset,assetpair) 
        ticker = Ticker(assetpair)
        asset_value_in_base_terms = float("{:.8f}".format(float(balances[1])*float(ticker)))
        equity = float("{:.8f}".format(float(balances[0]) + asset_value_in_base_terms))
        gap = Gap(equity, base_asset_percentage, asset_value_in_base_terms)
        print(f'{counter} loops --------------------------------------------PULSE')
        if hold(gap, assetpair):
            print("HOLD ORDER")
        else:
            orders +=1
            print("SEND ORDER")
        print(f'orders: {orders}')
        print(f'Equity {equity}')
        
        