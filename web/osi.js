/* ============================================================
   OSI Explorer front-end — POSTs a URL to /osi/api/analyze and
   renders the response as 7 OSI layer cards.
   ============================================================ */
(function () {
  'use strict';

  // ---- theme toggle (shared with portfolio) ----
  (function () {
    var root = document.documentElement, KEY = 'vt-theme';
    var labels = document.querySelectorAll('[data-theme-toggle] .tlabel');
    function sync(t){ root.setAttribute('data-theme', t); labels.forEach(function(e){ e.textContent = t==='dark'?'Light':'Dark'; }); }
    var cur = root.getAttribute('data-theme') || localStorage.getItem(KEY) || 'light';
    sync(cur);
    document.querySelectorAll('[data-theme-toggle]').forEach(function(b){
      b.addEventListener('click', function(){
        cur = root.getAttribute('data-theme')==='dark'?'light':'dark';
        try{ localStorage.setItem(KEY, cur); }catch(e){}
        sync(cur);
      });
    });
  })();

  var form = document.getElementById('form');
  var input = document.getElementById('url');
  var runBtn = document.getElementById('run');
  var schemeEl = document.getElementById('scheme');
  var notice = document.getElementById('notice');
  var summary = document.getElementById('summary');
  var legend = document.getElementById('legend');
  var layersEl = document.getElementById('layers');

  function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  // reference links — each layer + key protocol terminology
  var DOCS = {1:'Physical_layer',2:'Data_link_layer',3:'Network_layer',4:'Transport_layer',
              5:'Session_layer',6:'Presentation_layer',7:'Application_layer'};
  var TERMS = {
    'DNS':'Domain_Name_System','HTTP':'HTTP','TLS':'Transport_Layer_Security',
    'TCP':'Transmission_Control_Protocol','UDP':'User_Datagram_Protocol','IP':'Internet_Protocol',
    'Ethernet':'Ethernet','SNI':'Server_Name_Indication','ALPN':'Application-Layer_Protocol_Negotiation',
    'TTL':'Time_to_live','MAC address':'MAC_address','certificate':'Public_key_certificate',
    'cipher suite':'Cipher_suite','handshake':'Transport_Layer_Security#TLS_handshake',
    'ClientHello':'Transport_Layer_Security#TLS_handshake','ServerHello':'Transport_Layer_Security#TLS_handshake',
    'A record':'List_of_DNS_record_types','root server':'Root_name_server'
  };
  function wiki(slug){ return 'https://en.wikipedia.org/wiki/'+slug; }
  function ext(href,label,title){ return '<a href="'+href+'" target="_blank" rel="noopener"'+(title?' title="'+esc(title)+'"':'')+'>'+label+'</a>'; }
  function tlink(term,label){ var s=TERMS[term]; label=(label==null?term:label); return s?ext(wiki(s),esc(label),term+' — reference'):esc(label); }
  function cipherLink(name){
    if(!name) return '';
    var u = /^TLS_/.test(name) ? 'https://ciphersuite.info/cs/'+encodeURIComponent(name)+'/' : wiki('Cipher_suite');
    return ext(u, esc(name), 'cipher suite — reference');
  }
  // linkify protocol names in a proto label (DNS · HTTP · TLS · TCP · IP · Ethernet)
  function protoHtml(p){
    var out = esc(p);
    ['DNS','HTTP','TLS','TCP','IP','UDP','Ethernet'].forEach(function(t){
      out = out.replace(new RegExp('\\b'+t+'\\b'), ext(wiki(TERMS[t]), t, t+' — reference'));
    });
    return out;
  }

  function schemeOf(v){ v=v.trim().toLowerCase(); if(v.indexOf('http://')===0) return 'http'; if(v.indexOf('https://')===0) return 'https'; return 'https'; }
  input.addEventListener('input', function(){ schemeEl.textContent = schemeOf(input.value); });
  schemeEl.textContent = schemeOf(input.value);

  function kv(pairs){
    return '<dl class="kv">' + pairs.map(function(p){
      return '<dt>'+(p[3]?p[0]:esc(p[0]))+'</dt><dd>'+(p[2]?p[1]:esc(p[1]))+'</dd>';
    }).join('') + '</dl>';
  }

  // recursive DNS walk (root -> TLD -> authoritative)
  function traceHtml(tr){
    if(!tr || tr.error || !tr.hops || !tr.hops.length) return '';
    var rows = tr.hops.map(function(h){
      var lvl = h.level==='authoritative' ? 'auth' : h.level;
      var right;
      if(h.result==='referral') right='referral → <b>'+esc(h.zone)+'</b> <span style="color:var(--mute)">('+esc(h.next)+')</span>';
      else if(h.result==='answer') right='answer → <b>'+h.records.map(function(r){return esc(r.type+' '+r.data);}).join(', ')+'</b>';
      else if(h.result==='cname') right='CNAME → '+esc(h.cname);
      else right=esc(h.result)+' '+esc(h.detail||'');
      return '<div class="trow"><span class="tlvl">'+esc(lvl)+'</span><span class="tsrv">'+esc(h.server)+'</span><span class="tarr">'+right+'</span></div>';
    }).join('');
    return '<div class="sub-h">recursive resolution — root → TLD → authoritative</div>'+
      '<div class="trace">'+rows+'</div>'+
      '<div class="explain" style="margin-top:8px">The resolver walks the tree: a <b>root</b> server points to the <b>.com</b> servers, which point to the domain’s <b>authoritative</b> server, which finally returns the address. Each hop is a real query.</div>';
  }

  // TLS handshake ladder
  function ladderHtml(hs){
    if(!hs || !hs.steps) return '';
    var rows = hs.steps.map(function(s){
      return '<div class="lrow '+(s.from==='client'?'l-c':'l-s')+'">'+
        '<span class="lfrom">'+(s.from==='client'?'client →':'← server')+'</span>'+
        '<span class="lmsg">'+esc(s.msg)+(s.enc?' <span class="enc">🔒</span>':'')+'</span>'+
        '<span class="ldet">'+esc(s.detail)+'</span></div>';
    }).join('');
    return '<div class="sub-h">handshake — '+esc(hs.summary)+'</div><div class="ladder">'+rows+'</div>';
  }

  // prefer REAL captured handshake bytes (openssl -msg) over the canonical ladder
  function handshakeHtml(hs, wire){
    if(!(wire && wire.available && wire.messages && wire.messages.length)) return ladderHtml(hs);
    var rows = wire.messages.map(function(m){
      var arrow = m.dir==='client' ? 'client →' : '← server';
      return '<div class="lrow '+(m.dir==='client'?'l-c':'l-s')+'">'+
        '<span class="lfrom">'+arrow+'</span>'+
        '<span class="lmsg">'+esc(m.name)+' <span style="color:var(--mute)">('+m.length+' B)</span></span>'+
        '<span class="ldet hexb">'+esc(m.hex)+'…</span></div>';
    }).join('');
    return '<div class="sub-h">handshake — real bytes captured with <code>openssl s_client -msg</code></div><div class="ladder">'+rows+'</div>';
  }

  // full certificate chain (leaf → root), from openssl
  function chainHtml(wire){
    if(!(wire && wire.available && wire.chain && wire.chain.length)) return '';
    var n = wire.chain.length;
    var rows = wire.chain.map(function(c){
      var role = c.n===0 ? 'leaf' : (c.n===n-1 ? 'root' : 'intermediate');
      return '<div class="lrow"><span class="lfrom">'+role+'</span><span class="lmsg">'+esc(c.subject)+'</span></div>';
    }).join('');
    return '<div class="sub-h">certificate chain — leaf → root</div><div class="ladder">'+rows+'</div>';
  }

  // ---- build the 7 layers from the analysis ----
  function buildLayers(d){
    var https = d.scheme === 'https';
    var tls = d.tls;
    var L = [];

    // L7 Application ---------------------------------------------------
    var dns = d.dns, http = d.http;
    var dnsRows = kv([
      ['resolver', dns.resolver],
      ['txn id', '0x'+Number(dns.transaction_id).toString(16)],
      ['question', dns.question.name + '  (A, IN)'],
      ['answers', dns.answers.map(function(a){ return a.type+' '+a.data+'  <span style="color:var(--mute)">ttl '+a.ttl+'s</span>'; }).join('<br>'), true]
    ]);
    var respRows = [['status', '<b>'+esc(http.status_line)+'</b>', true]];
    ['Server','Content-Type','Content-Length','Location','Date'].forEach(function(h){
      if(http.response_headers[h]) respRows.push([h, http.response_headers[h]]);
    });
    var body7 =
      '<div class="sub-h">DNS &middot; name &rarr; address (UDP/53)</div>'+dnsRows+
      '<div class="hex">'+esc(dns.query_bytes)+'</div>'+
      traceHtml(dns.trace)+
      '<div class="sub-h">HTTP request</div>'+kv([
        ['request line', '<b>GET '+esc(http.request.path)+' HTTP/1.1</b>', true],
        ['Host', http.request.host],
        ['User-Agent', http.request.headers['User-Agent']]
      ])+
      '<div class="sub-h">HTTP response</div>'+kv(respRows)+
      '<div class="explain">The address bar name is turned into an IP by <b>DNS</b>, then <b>HTTP</b> carries the actual request/response.'+
        (https?' Over HTTPS the body is encrypted on the wire — shown here from our own client.':'')+'</div>';
    L.push({n:7, name:'Application', proto:'DNS · HTTP', kind:'real', open:true,
      adds:'adds the <b>real data</b> — the DNS query and the HTTP request/response', body:body7});

    // L6 Presentation --------------------------------------------------
    if(https && tls){
      var c = tls.cert || {};
      var body6 = kv([
        ['TLS version', '<b>'+esc(tls.version)+'</b>', true],
        ['cipher', '<b>'+cipherLink(tls.cipher)+'</b> ('+tls.bits+'-bit)', true],
        ['cert subject', c.subject_cn],
        ['cert issuer', (c.issuer_cn||'')+(c.issuer_org?' · '+c.issuer_org:'')],
        ['valid', (c.not_before||'?')+'  →  '+(c.not_after||'?')],
        ['SAN', (c.sans||[]).join(', ') + (c.san_count>((c.sans||[]).length)?' …':'')]
      ]) + chainHtml(tls.wire) + '<div class="explain">This layer <b>encrypts</b> the data and proves the server’s identity with an X.509 <b>'+tlink('certificate','certificate')+'</b>, using the cipher agreed in the '+tlink('handshake','handshake')+'.</div>';
      L.push({n:6, name:'Presentation', proto:'TLS', kind:'real', adds:'adds <b>encryption</b> + certificate (serialisation)', body:body6});
    } else {
      L.push({n:6, name:'Presentation', proto:'—', kind:'illus',
        adds:'no TLS on plain HTTP', body:'<div class="explain">This is a plain <b>http://</b> request, so there is no encryption layer — everything travels in <b>cleartext</b>. That is exactly why HTTPS exists.</div>'});
    }

    // L5 Session -------------------------------------------------------
    if(https && tls){
      var chosen = tls.cipher;
      var chips = (tls.offered_sample||[]).map(function(c){
        var href = /^TLS_/.test(c) ? 'https://ciphersuite.info/cs/'+encodeURIComponent(c)+'/' : wiki('Cipher_suite');
        return '<a class="chip'+(c===chosen?' on':'')+'" href="'+href+'" target="_blank" rel="noopener" title="cipher suite — reference">'+esc(c)+'</a>';
      }).join('');
      var body5 = kv([
        [tlink('SNI','SNI'), '<b>'+esc(tls.sni)+'</b>', true, true],
        [tlink('ALPN','ALPN'), tls.alpn || '—', false, true],
        ['ciphers offered', tls.offered_count + '  ('+tlink('ClientHello','ClientHello')+')', true],
        ['cipher chosen', '<b>'+cipherLink(chosen)+'</b>  ('+tlink('ServerHello','ServerHello')+')', true]
      ]) + '<div class="sub-h">negotiation — offered vs chosen</div><div class="chips">'+chips+'</div>'+
        handshakeHtml(tls.handshake, tls.wire)+
        '<div class="explain">The '+tlink('handshake','handshake')+' opens the secure session: the client sends a '+tlink('ClientHello','ClientHello')+' listing '+tls.offered_count+' ciphers and the '+tlink('SNI','SNI')+'; the server replies '+tlink('ServerHello','ServerHello')+' picking one. That agreement is the negotiation.</div>';
      L.push({n:5, name:'Session', proto:'TLS handshake', kind:'real', adds:'establishes the <b>session</b> (TLS handshake)', body:body5});
    } else {
      L.push({n:5, name:'Session', proto:'TCP connection', kind:'recon',
        adds:'the TCP connection acts as the session', body:'<div class="explain">With no TLS, the "session" is just the open <b>TCP connection</b> between the two sockets.</div>'});
    }

    // L4 Transport -----------------------------------------------------
    var tcp = d.tcp;
    var body4 = kv([
      ['protocol', 'TCP'],
      ['source port', '<b>'+tcp.src_port+'</b> (ephemeral)', true],
      ['dest port', '<b>'+tcp.dst_port+'</b> ('+(https?'https':'http')+')', true],
      ['handshake', 'SYN → SYN,ACK → ACK']
    ]) + '<div class="explain">TCP adds <b>ports</b> (which app the data belongs to) and reliable, ordered delivery via the 3-way <b>handshake</b>, sequence and ACK numbers. <span style="color:var(--recon)">The individual handshake packets/seq numbers are reconstructed here, not sniffed.</span></div>';
    L.push({n:4, name:'Transport', proto:'TCP', kind:'recon', adds:'adds <b>ports</b> + reliable delivery (TCP header)', body:body4});

    // L3 Network -------------------------------------------------------
    var body3 = kv([
      ['source IP', '<b>'+esc(tcp.src_ip)+'</b>', true],
      ['dest IP', '<b>'+esc(tcp.dst_ip)+'</b>', true],
      ['protocol', 'TCP (6)'],
      ['TTL', 'decremented at each router hop']
    ]) + '<div class="explain">IP adds the <b>source and destination addresses</b> so routers can forward the packet across networks toward the server.</div>';
    L.push({n:3, name:'Network', proto:'IP', kind:'real', adds:'adds <b>IP addresses</b> for routing', body:body3});

    // L2 Data Link -----------------------------------------------------
    L.push({n:2, name:'Data Link', proto:'Ethernet', kind:'illus', adds:'adds <b>MAC addresses</b> for the first hop',
      body: kv([['source MAC','your NIC (virtual on a cloud VM)'],['dest MAC','the default-gateway router']]) +
        '<div class="explain">Ethernet frames the packet with <b>MAC addresses</b> for the next physical hop (your machine → the gateway). On a cloud VM the NIC is virtualised, so this is illustrated.</div>'});

    // L1 Physical ------------------------------------------------------
    L.push({n:1, name:'Physical', proto:'bits', kind:'illus', adds:'transmits the raw <b>bits</b>',
      body:'<div class="explain">Finally the frame becomes <b>electrical/optical/radio signals</b> on the wire — 1s and 0s on the medium. There are no "packets" to capture at this layer.</div>'});

    return L;
  }

  function render(d){
    summary.hidden = false; legend.hidden = false;
    summary.innerHTML =
      '<span>'+esc(d.scheme)+'://'+esc(d.host)+'</span>'+
      '<span>&rarr; <b>'+esc(d.tcp.dst_ip)+'</b>:'+d.tcp.dst_port+'</span>'+
      (d.tls?'<span>TLS <b>'+esc(d.tls.version.replace('TLSv',''))+'</b></span>':'<span>no TLS</span>')+
      '<span>'+esc((d.http.status_line||'').replace('HTTP/1.1 ',''))+'</span>';

    var layers = buildLayers(d);
    layersEl.innerHTML = layers.map(function(l){
      var tag = l.kind==='real'?'<span class="tag real">real</span>':
                l.kind==='recon'?'<span class="tag recon">reconstructed</span>':
                '<span class="tag illus">illustrated</span>';
      var doc = ext(wiki(DOCS[l.n]), 'what’s this? ↗', 'What is the '+l.name+' layer?');
      return '<div class="layer on-'+l.kind+(l.open?' open':'')+'">'+
        '<div class="lhead"><span class="lnum">L'+l.n+'</span>'+
          '<span class="lname">'+l.name+'</span><span class="lproto">'+protoHtml(l.proto)+'</span>'+
          '<span class="ldoc">'+doc+'</span>'+tag+'<span class="lchev">▸</span></div>'+
        '<div class="lbody"><div class="ladds">'+l.adds+'</div>'+l.body+'</div></div>';
    }).join('');
    layersEl.querySelectorAll('.lhead').forEach(function(h){
      h.addEventListener('click', function(e){ if(e.target.closest('a')) return; h.parentNode.classList.toggle('open'); });
    });
  }

  function send(){
    var url = input.value.trim();
    if(!url) return;
    notice.hidden = true;
    runBtn.disabled = true; runBtn.textContent = '…';
    fetch('/osi/api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:url})})
      .then(function(r){ return r.json().then(function(j){ return {ok:r.ok, data:j}; }); })
      .then(function(res){
        if(res.ok && res.data.ok){ render(res.data); }
        else { summary.hidden=true; legend.hidden=true; layersEl.innerHTML='';
               notice.hidden=false; notice.textContent = (res.data && res.data.error) || 'Request failed.'; }
      })
      .catch(function(){ notice.hidden=false; notice.textContent='Network error — could not reach the server.'; })
      .then(function(){ runBtn.disabled=false; runBtn.textContent='Run'; });
  }

  form.addEventListener('submit', function(e){ e.preventDefault(); send(); });

  // shareable / deep-link: /osi/?url=https://example.com auto-runs
  var qp = new URLSearchParams(location.search).get('url');
  if (qp){ input.value = qp; schemeEl.textContent = schemeOf(qp); send(); }
})();
