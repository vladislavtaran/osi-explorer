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

  function schemeOf(v){ v=v.trim().toLowerCase(); if(v.indexOf('http://')===0) return 'http'; if(v.indexOf('https://')===0) return 'https'; return 'https'; }
  input.addEventListener('input', function(){ schemeEl.textContent = schemeOf(input.value); });
  schemeEl.textContent = schemeOf(input.value);

  function kv(pairs){
    return '<dl class="kv">' + pairs.map(function(p){
      return '<dt>'+esc(p[0])+'</dt><dd>'+(p[2]?p[1]:esc(p[1]))+'</dd>';
    }).join('') + '</dl>';
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
        ['cipher', '<b>'+esc(tls.cipher)+'</b> ('+tls.bits+'-bit)', true],
        ['cert subject', c.subject_cn],
        ['cert issuer', (c.issuer_cn||'')+(c.issuer_org?' · '+c.issuer_org:'')],
        ['valid', (c.not_before||'?')+'  →  '+(c.not_after||'?')],
        ['SAN', (c.sans||[]).join(', ') + (c.san_count>((c.sans||[]).length)?' …':'')]
      ]) + '<div class="explain">This layer <b>encrypts</b> the data and proves the server’s identity with an X.509 <b>certificate</b>, using the cipher agreed in the handshake.</div>';
      L.push({n:6, name:'Presentation', proto:'TLS', kind:'real', adds:'adds <b>encryption</b> + certificate (serialisation)', body:body6});
    } else {
      L.push({n:6, name:'Presentation', proto:'—', kind:'illus',
        adds:'no TLS on plain HTTP', body:'<div class="explain">This is a plain <b>http://</b> request, so there is no encryption layer — everything travels in <b>cleartext</b>. That is exactly why HTTPS exists.</div>'});
    }

    // L5 Session -------------------------------------------------------
    if(https && tls){
      var chosen = tls.cipher;
      var chips = (tls.offered_sample||[]).map(function(c){ return '<span class="chip'+(c===chosen?' on':'')+'">'+esc(c)+'</span>'; }).join('');
      var body5 = kv([
        ['SNI', '<b>'+esc(tls.sni)+'</b>', true],
        ['ALPN', tls.alpn || '—'],
        ['ciphers offered', tls.offered_count + '  (ClientHello)'],
        ['cipher chosen', '<b>'+esc(chosen)+'</b>  (ServerHello)', true]
      ]) + '<div class="sub-h">negotiation — offered vs chosen</div><div class="chips">'+chips+'</div>'+
        '<div class="explain">The <b>handshake</b> opens the secure session: the client sends a <b>ClientHello</b> listing '+tls.offered_count+' ciphers and the SNI; the server replies <b>ServerHello</b> picking one. That agreement is the negotiation.</div>';
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
      return '<div class="layer on-'+l.kind+(l.open?' open':'')+'">'+
        '<div class="lhead"><span class="lnum">L'+l.n+'</span>'+
          '<span class="lname">'+l.name+'</span><span class="lproto">'+l.proto+'</span>'+
          tag+'<span class="lchev">▸</span></div>'+
        '<div class="lbody"><div class="ladds">'+l.adds+'</div>'+l.body+'</div></div>';
    }).join('');
    layersEl.querySelectorAll('.lhead').forEach(function(h){
      h.addEventListener('click', function(){ h.parentNode.classList.toggle('open'); });
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
})();
