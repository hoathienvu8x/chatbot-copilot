https://www.investing.com/indices/us-spx-500 (S&P 500)
https://www.investing.com/indices/us-30 (Dow Jones Industrial)
https://www.investing.com/indices/nasdaq-composite (NASDAQ)
https://www.investing.com/currencies/us-dollar-index (USD Dollar Index)
https://www.investing.com/commodities/gold (Gold)
https://www.investing.com/commodities/silver (Silver)
https://www.investing.com/currencies/eur-usd (Euro US Dollar)
https://www.investing.com/currencies/usd-brl ( US Dollar Brazil Real)

var pids = [
    {
        "pid": "2103",
        "name": "USD/BRL",
        "symbol": "^USDBRL"
    },
    {
        "pid": "1",
        "name": "EUR/USD",
        "symbol":"E6Y00",
    },
    {
        "pid": "8836",
        "name": "Silver",
        "symbol":"SI*1"
    },
    {
        "pid": "8830",
        "name": "Gold",
        "symbol": "GC*1"
    },
    {
        "pid": "8827",
        "name": "Dollar Index Futures",
        "symbol":"DXY00"
    },
    {
        "pid": "14958",
        "name": "Nasdaq",
        "symbol":"$NASX"
    },
    {
        "pid": "169",
        "name": "Dow Jones",
        "symbol":"$INDU"
    },
    {
        "pid": "166",
        "name": "S&P 500",
        "symbol":"$SPX"
    }
];
const SYMBOL_KEYS = [
  'name', 'last', 'change', 'ptcchange', 'volume', 'high', 'low', 'open',
  'previous', 'opint', 'bid', 'bidsize', 'ask', 'asksize', 'time', 'month'
];
String.prototype.to_number = function () {
  var s = this.replace(/[^\d.-]/g, '');
  s = s.replace(/[\.]+$/, '');
  if (s.length == 0) return 0;
  if (s.length == 1 && s == '-') return 0;
  return Number(s);
};
var nmaps = {};
for (var i in pids) {
  nmaps[pids[i].pid] = {
    name: pids[i].symbol,
    month: pids[i].name
  };
}

function exx(m) {
  if (m[0] != 'a') return;
  var lst = [];
  try {
    lst = JSON.parse(m.substring(1));
    if (!Array.isArray(lst)) {
      lst = [];
    }
  } catch {
    lst = [];
  }
  if (lst.length == 0) {
    return;
  }
  var obj = null;
  if (typeof lst[0] == 'string') {
    try {
      obj = JSON.parse(lst[0]);
    } catch {
      obj = null;
    }
  }
  if (!obj || !obj.hasOwnProperty('message')) return;
  if (typeof obj.message != 'string') return;
  var s = obj.message;
  if (obj.message.indexOf('::{') != -1) {
    s = '{'+obj.message.split('::{').pop();
  }
  var v = null;
  try {
    v = JSON.parse(s);
  } catch {
    v = null;
  }
  if (!v) return;
  var o = {};
  for (var k in v) {
    if (['last_dir','pc_col','pid'].includes(k) == true) continue;
    if (k == 'last') {
      if (v.hasOwnProperty('last_numeric')) continue;
    }
    if (k == 'turnover') {
      if (v.hasOwnProperty('turnover_numeric')) continue;
    }
    if (k == 'time') {
      if (v.hasOwnProperty('timestamp')) continue;
    }
    if (k == 'last_numeric') {
      o['last'] = v[k];
    } else if (k == 'turnover_numeric') {
      o['volume'] = v[k];
    } else if (k == 'timestamp') {
      o['time'] = v[k];
    } else if (k == 'last_close') {
      o['settle'] = v[k];
    } else if (k == 'pc') {
      o['change'] = v[k];
    } else if (k == 'pcp') {
      o['ptcchange'] = v[k];
    } else {
      o[k] = v[k];
    }
  }
  for (var k in o) {
    if (typeof o[k] == 'string') {
      o[k] = o[k].to_number();
    }
  }
  if (o.hasOwnProperty('last') && o.hasOwnProperty('change')) {
    o.previous = o.last - o.change;
  }
  if (v.hasOwnProperty('pid')) {
    var pid = v.pid;
    if (nmaps.hasOwnProperty(pid)) {
      o.name = nmaps[pid].name;
      o.month = nmaps[pid].month;
    }
  }
  for (var i in SYMBOL_KEYS) {
    if(!o.hasOwnProperty(SYMBOL_KEYS[i])) {
      o[SYMBOL_KEYS[i]] = 0;
    }
  }
  console.log(o);
}

ws = new WebSocket('wss://streaming.forexpros.com/echo/596/stblujvi/websocket');
ws.onmessage = function(e) {
  var m = (e.data || '').trim();
  if (m.length == 0) return;
  exx(m);
};

function bmsg(obj) {
  return JSON.stringify(obj,false);
}

x = {
  "_event": "bulk-subscribe",
  "tzID": 8,
  "message": "isOpenExch-2:%%isOpenExch-1:%%pid-8849:%%isOpenExch-1004:%%pid-8833:%%pid-8862:%%pid-8830:%%pid-8836:%%pid-8831:%%pid-8916:%%pid-23705:%%pid-23706:%%pid-23703:%%pid-23698:%%pid-8880:%%isOpenExch-118:%%pid-8895:%%pid-1141794:%%pid-6408:%%pid-6497:%%pid-6369:%%pid-13994:%%pid-6435:%%pid-13063:%%pid-26490:%%pid-941155:%%pid-169:%%pid-20:%%pid-166:%%pid-172:%%isOpenExch-4:%%pid-27:%%isOpenExch-3:%%pid-167:%%isOpenExch-9:%%pid-178:%%isOpenExch-20:%%isOpenExch-NaN:%%pid-1166239:%%pid-16678:%%pid-17195:%%pid-1131557:%%pid-251:%%pid-6520:%%pid-32306:%%pid-252:%%pid-13969:%%pid-8274:%%pid-1:%%isOpenExch-1002:%%pid-2:%%pid-3:%%pid-5:%%pid-7:%%pid-9:%%pid-10:%%pid-8832:%%pid-1175152:%%isOpenExch-152:%%pid-1175153:%%pid-14958:%%pid-44336:%%isOpenExch-97:%%pid-8827:%%pid-8911:%%pidExt-8911:%%cmt-1-5-8911:%%pid-8919:%%pid-8988:%%pid-8894:%%pid-1174944:%%pid-964526:%%pid-13916:%%pid-8860:%%pid-1175151:"
};
y = {
    "_event": "UID",
    "UID": 200514945
};
mm = [...pids.map(function(v) {
  return 'pid-'+v.pid+':';
}), ...pids.map(function(v) {
  return 'pidExt-'+v.pid+':';
})]

ws.send(bmsg([
  bmsg({
    "_event": "bulk-subscribe",
    "tzID": 7,
    "message": mm.join('%%')
  })
]));

// ws.send(JSON.stringify([JSON.stringify(x,false)],false));
