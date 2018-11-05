import json
import blockchain

misperrors = {'error': 'Error'}
mispattributes = {'input': ['btc'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Steve Clement',
              'description': 'Simple BTC expansion service to \
                              get quick information from MISP attributes',
              'module-type': ['expansion', 'hover']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('btc'):
        toquery = request['btc']
    else:
        return False

    try:
        address = blockchain.blockexplorer.get_address(toquery)
    except Exception as e:
        misperrors['error'] = e
        return misperrors
    finalBalance = address.final_balance*(1/100000000)
    totalRX = address.total_received*(1/100000000)
    totalTX = address.total_sent*(1/100000000)
    totalTransactions = address.n_tx

    answer = 'Current balance: \
        {} - \
        {} total received - \
        {} total sent - \
        {} transactions.\
        '.format(finalBalance, totalRX, totalTX, totalTransactions)
    r = {'results': [{'types': mispattributes['output'],
                      'values':[str(answer)]}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
