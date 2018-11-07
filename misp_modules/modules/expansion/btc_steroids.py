import sys
import json
import requests
import time

misperrors = {'error': 'Error'}
mispattributes = {'input': ['btc'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Sascha Rommelfangen',
              'description': 'BTC expansion service to \
                              get quick information from MISP attributes',
              'module-type': ['hover']}

moduleconfig = []

blockchain_firstseen='https://blockchain.info/q/addressfirstseen/'
blockchain_balance='https://blockchain.info/q/addressbalance/'
blockchain_totalreceived='https://blockchain.info/q/getreceivedbyaddress/'
blockchain_all='https://blockchain.info/rawaddr/'
converter = 'https://min-api.cryptocompare.com/data/pricehistorical?fsym=BTC&tsyms=USD,EUR&ts='
converter_rls = 'https://min-api.cryptocompare.com/stats/rate/limit'
result_text = ""
g_rate_limit = 300
start_time = 0
conversion_rates = {}

def get_consumption(output=False):
    req = requests.get(converter_rls)
    jreq = req.json()
    minute = str(jreq['Minute']['CallsLeft']['Histo'])
    hour   = str(jreq['Hour']['CallsLeft']['Histo'])
    # Debug out for the console
    print("Calls left this minute / hour: " + minute + " / " + hour)
    return minute, hour


def convert(btc, timestamp):
    global g_rate_limit
    global start_time
    global now
    global conversion_rates
    date = time.strftime('%Y-%m-%d', time.localtime(timestamp))
    # Lookup conversion rates in the cache:
    if date in conversion_rates:
        (usd, eur) = conversion_rates[date]
    else:
        # If not cached, we have to get the converion rates
        # We have to be careful with rate limiting on the server side
        if g_rate_limit == 300:
            minute, hour = get_consumption()
        g_rate_limit -= 1
        now = time.time()
        delta = now - start_time
        #print(g_rate_limit)
        if g_rate_limit <= 10:
            minute, hour = get_consumption(output=True)
            if int(minute) <= 10:
                #print(minute)
                #get_consumption(output=True)
                time.sleep(3)
            else:
                mprint(minute)
                start_time = time.time()
                g_rate_limit = int(minute)
        try:
            req = requests.get(converter+str(timestamp))
            jreq = req.json()
            usd = jreq['BTC']['USD']
            eur = jreq['BTC']['EUR']
            # Since we have the rates, store them in the cache
            conversion_rates[date] = (usd, eur)
        except Exception as ex:
            mprint(ex)
            get_consumption(output=True)
    # Actually convert and return the values
    u = usd * btc
    e = eur * btc
    return u,e


def mprint(input):
    # Prepare the final print
    global result_text
    result_text = result_text + "\n" + str(input)


def handler(q=False):
    global result_text
    global conversion_rates
    start_time = time.time()
    now = time.time()
    if q is False:
        return False
    request = json.loads(q)
    click = False
    # This means the magnifying glass has been clicked
    if request.get('persistent') == 1:
        click = True
    # Otherwise the attribute was only hovered over
    if request.get('btc'):
        btc = request['btc']
    else:
        return False

    mprint("\nAddress:\t" + btc)
    try:
        req = requests.get(blockchain_all+btc+"?limit=50&filter=5")
        jreq = req.json()
    except Exception as e:
        #print(e)
        print(req.text)
        result_text = ""
        sys.exit(1) 

    n_tx = jreq['n_tx']
    balance = float(jreq['final_balance'] / 100000000)
    rcvd = float(jreq['total_received'] / 100000000)
    sent = float(jreq['total_sent'] / 100000000)
    output = 'Balance:\t{0:.10f} BTC (+{1:.10f} BTC / -{2:.10f} BTC)'
    mprint(output.format(balance, rcvd, sent))
    if click is False:
        mprint("Transactions:\t" + str(n_tx) + "\t (previewing up to 5 most recent)")
    else:
        mprint("Transactions:\t" + str(n_tx))
    mprint("======================================================================================")
    i = 0
    while i < n_tx:
        if click is False:
            req = requests.get(blockchain_all+btc+"?limit=5&offset="+str(i)+"&filter=5")
            if n_tx > 5:
                n_tx = 5
        else:
            req = requests.get(blockchain_all+btc+"?limit=50&offset="+str(i)+"&filter=5")
        jreq = req.json()
        if jreq['txs']:
            for transactions in jreq['txs']:
                sum = 0
                sum_counter = 0
                for tx in transactions['inputs']:
                    script_old = tx['script']
                    if tx['prev_out']['value'] != 0 and tx['prev_out']['addr'] == btc:
                        datetime = time.strftime("%d %b %Y %H:%M:%S %Z", time.localtime(int(transactions['time'])))
                        value = float(tx['prev_out']['value'] / 100000000 )
                        u,e = convert(value, transactions['time'])
                        mprint("#" + str(n_tx - i) + "\t" + str(datetime) + "\t-{0:10.8f} BTC {1:10.2f} USD\t{2:10.2f} EUR".format(value, u, e).rstrip('0'))
                        if script_old != tx['script']:
                            i += 1
                        else:
                            sum_counter += 1
                            sum += value
                if sum_counter > 1:
                    u,e = convert(sum, transactions['time'])
                    mprint("\t\t\t\t\t----------------------------------------------")
                    mprint("#" + str(n_tx - i) + "\t\t\t\t  Sum:\t-{0:10.8f} BTC {1:10.2f} USD\t{2:10.2f} EUR\n".format(sum, u, e).rstrip('0'))
                for tx in transactions['out']:
                    if tx['value'] != 0 and tx['addr'] == btc:
                        datetime = time.strftime("%d %b %Y %H:%M:%S %Z", time.localtime(int(transactions['time'])))
                        value = float(tx['value'] / 100000000 )
                        u,e = convert(value, transactions['time'])
                        mprint("#" + str(n_tx - i) + "\t" + str(datetime) + "\t {0:10.8f} BTC {1:10.2f} USD\t{2:10.2f} EUR".format(value, u, e).rstrip('0'))
                        #i += 1
                i += 1

    r = { 
        'results': [
            {
                'types': ['text'],
                'values':[
                    str(result_text)
                ]
            }
        ]
    }
    # Debug output on the console
    print(result_text)
    # Unset the result for the next request
    result_text = ""
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
