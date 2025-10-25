const __defProp = Object.defineProperty;
const __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/converter/linkParser.js
function decodeBase64(str) {
  if (typeof atob === "function") {
    return atob(str);
  }
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;
  let char1, char2, char3;
  let enc1, enc2, enc3, enc4;
  str = str.replace(/[^A-Za-z0-9+/=]/g, "");
  while (i < str.length) {
    enc1 = base64Chars.indexOf(str.charAt(i++));
    enc2 = base64Chars.indexOf(str.charAt(i++));
    enc3 = base64Chars.indexOf(str.charAt(i++));
    enc4 = base64Chars.indexOf(str.charAt(i++));
    char1 = enc1 << 2 | enc2 >> 4;
    char2 = (enc2 & 15) << 4 | enc3 >> 2;
    char3 = (enc3 & 3) << 6 | enc4;
    result += String.fromCharCode(char1);
    if (enc3 !== 64) result += String.fromCharCode(char2);
    if (enc4 !== 64) result += String.fromCharCode(char3);
  }
  return result;
}
__name(decodeBase64, "decodeBase64");
function parseV2RayLink(link) {
  try {
    if (link.startsWith("vmess://")) {
      const base64 = link.substring(8);
      const decoded = decodeBase64(base64);
      let config;
      try {
        config = JSON.parse(decoded);
      } catch (e) {
        const match = decoded.match(/{"v":"\d+".*}/);
        if (match) {
          config = JSON.parse(match[0]);
        } else {
          throw new Error("Format VMess tidak valid");
        }
      }
      return {
        type: "vmess",
        name: config.ps || `VMess-${config.add}:${config.port}`,
        server: config.add,
        port: config.port,
        uuid: config.id,
        alterId: config.aid || 0,
        cipher: config.scy || "auto",
        tls: config.tls === "tls",
        skipCertVerify: false,
        network: config.net || "tcp",
        wsPath: config.path || "",
        wsHost: config.host || config.add,
        sni: config.sni || config.host || config.add
      };
    }
    if (link.startsWith("vless://")) {
      return parseVLESSLink(link);
    }
    if (link.startsWith("trojan://")) {
      return parseTrojanLink(link);
    }
    if (link.startsWith("ss://")) {
      return parseShadowsocksLink(link);
    }
    throw new Error("Unsupported link type");
  } catch (error) {
    console.error(`Failed to parse link: ${link}`, error);
    throw new Error(`Gagal parsing link VMess: ${error.message}`);
  }
}
__name(parseV2RayLink, "parseV2RayLink");
function parseVLESSLink(link) {
  const url = new URL(link);
  const params = new URLSearchParams(url.search);
  return {
    type: "vless",
    name: decodeURIComponent(url.hash.substring(1)),
    server: url.hostname,
    port: parseInt(url.port),
    uuid: url.username,
    tls: params.get("security") === "tls",
    skipCertVerify: false,
    network: params.get("type") || "tcp",
    wsPath: params.get("path") || "",
    wsHost: params.get("host") || url.hostname,
    sni: params.get("sni") || params.get("host") || url.hostname
  };
}
__name(parseVLESSLink, "parseVLESSLink");
function parseTrojanLink(link) {
  const url = new URL(link);
  const params = new URLSearchParams(url.search);
  return {
    type: "trojan",
    name: decodeURIComponent(url.hash.substring(1)),
    server: url.hostname,
    port: parseInt(url.port),
    password: url.username,
    tls: params.get("security") === "tls",
    skipCertVerify: false,
    network: params.get("type") || "tcp",
    wsPath: params.get("path") || "",
    wsHost: params.get("host") || url.hostname,
    sni: params.get("sni") || params.get("host") || url.hostname
  };
}
__name(parseTrojanLink, "parseTrojanLink");
function parseShadowsocksLink(link) {
  const url = new URL(link);
  const params = new URLSearchParams(url.search);
  if (params.get("plugin") === "v2ray-plugin" || params.get("type") === "ws") {
    return {
      type: "ss",
      name: decodeURIComponent(url.hash.substring(1)),
      server: url.hostname,
      port: parseInt(url.port),
      cipher: url.protocol.substring(3) || "none",
      password: url.username,
      tls: params.get("security") === "tls",
      skipCertVerify: false,
      network: params.get("type") || "tcp",
      wsPath: params.get("path") || "",
      wsHost: params.get("host") || url.hostname,
      sni: params.get("sni") || params.get("host") || url.hostname
    };
  }
  throw new Error("Shadowsocks link invalid");
}
__name(parseShadowsocksLink, "parseShadowsocksLink");

// src/converter/configGenerators.js
function generateClashConfig(links, isFullConfig = false) {
  const parsedLinks = links.map((link) => parseV2RayLink(link));
  let config = `# Clash Configuration
# Generated at: ${(/* @__PURE__ */ new Date()).toISOString()}

`;
  if (isFullConfig) {
    config += `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: redir-host
  nameserver:
    - 8.8.8.8
    - https://dns.google/dns-query
  fallback:
    - 8.8.4.4
    - https://dns.google/dns-query

rule-providers:
   ADS:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/malikshi/open_clash/main/rule_provider/rule_basicads.yaml"
    path: "./rule_provider/rule_basicads.yaml"
    interval: 86400

   Porn:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/malikshi/open_clash/main/rule_provider/rule_porn.yaml"
    path: "./rule_provider/rule_porn.yaml"
    interval: 86400

`;
  }
  config += `proxies:
`;
  parsedLinks.forEach((link) => {
    config += `  - name: "${link.name}"
`;
    config += `    type: ${link.type}
`;
    config += `    server: ${link.server}
`;
    config += `    port: ${link.port}
`;
    if (link.type === "vmess") {
      config += `    uuid: ${link.uuid}
`;
      config += `    alterId: ${link.alterId}
`;
      config += `    cipher: ${link.cipher}
`;
    } else if (link.type === "vless") {
      config += `    uuid: ${link.uuid}
`;
    } else if (link.type === "trojan") {
      config += `    password: ${link.password}
`;
    } else if (link.type === "ss") {
      config += `    cipher: ${link.cipher}
`;
      config += `    password: ${link.password}
`;
    }
    config += `    udp: true
`;
    if (link.tls) {
      config += `    tls: true
`;
      config += `    skip-cert-verify: ${link.skipCertVerify}
`;
      if (link.sni) {
        config += `    servername: ${link.sni}
`;
      }
    }
    if (link.network === "ws") {
      config += `    network: ws
`;
      config += `    ws-opts:
`;
      config += `      path: "${link.wsPath}"
`;
      if (link.wsHost) {
        config += `      headers:
`;
        config += `        Host: "${link.wsHost}"
`;
      }
    }
    config += "\n";
  });
  if (isFullConfig) {
    config += `proxy-groups:
  - name: "INTERNET"
    type: select
    proxies:
      - "BALANCED"
      - "SELECTOR"
      - "BEST-PING"
      - "DIRECT"
      - "REJECT"

  - name: "SELECTOR"
    type: select
    proxies:
      - "DIRECT"
      - "REJECT"
`;
    parsedLinks.forEach((link) => {
      config += `      - "${link.name}"
`;
    });
    config += `
  - name: "BEST-PING"
    type: url-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    proxies:
`;
    parsedLinks.forEach((link) => {
      config += `      - "${link.name}"
`;
    });
    config += `
  - name: "BALANCED"
    type: load-balance
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
    proxies:
`;
    parsedLinks.forEach((link) => {
      config += `      - "${link.name}"
`;
    });
    config += `
  - name: "PORN"
    type: select
    proxies:
      - "REJECT"
      - "SELECTOR"

  - name: "ADS"
    type: select
    proxies:
      - "REJECT"
      - "SELECTOR"

rules:
  - RULE-SET, ADS,ADS
  - RULE-SET, Porn,PORN
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - MATCH,INTERNET
`;
  }
  return config;
}
__name(generateClashConfig, "generateClashConfig");
function generateNekoboxConfig(links, isFullConfig = false) {
  const parsedLinks = links.map((link) => parseV2RayLink(link));
  let config = isFullConfig ? `{
  "dns": {
    "final": "dns-final",
    "independent_cache": true,
    "rules": [
      {
        "disable_cache": false,
        "domain": [
          "family.cloudflare-dns.com"
        ],
        "server": "direct-dns"
      }
    ],
    "servers": [
      {
        "address": "https://family.cloudflare-dns.com/dns-query",
        "address_resolver": "direct-dns",
        "strategy": "ipv4_only",
        "tag": "remote-dns"
      },
      {
        "address": "local",
        "strategy": "ipv4_only",
        "tag": "direct-dns"
      },
      {
        "address": "local",
        "address_resolver": "dns-local",
        "strategy": "ipv4_only",
        "tag": "dns-final"
      },
      {
        "address": "local",
        "tag": "dns-local"
      },
      {
        "address": "rcode://success",
        "tag": "dns-block"
      }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "../cache/clash.db",
      "store_fakeip": true
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "../files/yacd"
    }
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "listen_port": 6450,
      "override_address": "8.8.8.8",
      "override_port": 53,
      "tag": "dns-in",
      "type": "direct"
    },
    {
      "domain_strategy": "",
      "endpoint_independent_nat": true,
      "inet4_address": [
        "172.19.0.1/28"
      ],
      "mtu": 9000,
      "sniff": true,
      "sniff_override_destination": true,
      "stack": "system",
      "tag": "tun-in",
      "type": "tun"
    },
    {
      "domain_strategy": "",
      "listen": "0.0.0.0",
      "listen_port": 2080,
      "sniff": true,
      "sniff_override_destination": true,
      "tag": "mixed-in",
      "type": "mixed"
    }
  ],
  "log": {
    "level": "info"
  },
  "outbounds": [
    {
      "tag": "Internet",
      "type": "selector",
      "outbounds": [
        "Best Latency",
` : `{
  "outbounds": [
`;
  parsedLinks.forEach((link) => {
    config += `        "${link.name}",
`;
  });
  if (isFullConfig) {
    config += `        "direct"
      ]
    },
    {
      "type": "urltest",
      "tag": "Best Latency",
      "outbounds": [
`;
    parsedLinks.forEach((link) => {
      config += `        "${link.name}",
`;
    });
    config += `        "direct"
      ],
      "url": "https://detectportal.firefox.com/success.txt",
      "interval": "1m0s"
    },
`;
  }
  parsedLinks.forEach((link, index) => {
    if (index > 0) config += ",\n";
    config += `    {
`;
    config += `      "tag": "${link.name}",
`;
    if (link.type === "vmess") {
      config += `      "type": "vmess",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "alter_id": ${link.alterId || 0},
`;
      config += `      "security": "${link.cipher || "auto"}",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "vless") {
      config += `      "type": "vless",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "flow": "",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "trojan") {
      config += `      "type": "trojan",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "password": "${link.password}",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "ss") {
      config += `      "type": "shadowsocks",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "method": "${link.cipher || "none"}",
`;
      config += `      "password": "${link.password}",
`;
      config += `      "plugin": "v2ray-plugin",
`;
      config += `      "plugin_opts": "mux=0;path=${link.wsPath};host=${link.wsHost || link.server};tls=${link.tls ? "1" : "0"}"
`;
    }
    config += `    }`;
  });
  if (isFullConfig) {
    config += `,
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "bypass",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "outbound": "dns-out",
        "port": [
          53
        ]
      },
      {
        "inbound": [
          "dns-in"
        ],
        "outbound": "dns-out"
      },
      {
        "network": [
          "udp"
        ],
        "outbound": "block",
        "port": [
          443
        ],
        "port_range": []
      },
      {
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "outbound": "block",
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ]
      }
    ]
  }
}`;
  } else {
    config += `
  ]
}`;
  }
  return config;
}
__name(generateNekoboxConfig, "generateNekoboxConfig");
function generateSingboxConfig(links, isFullConfig = false) {
  const parsedLinks = links.map((link) => parseV2RayLink(link));
  let config = isFullConfig ? `{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "tag": "remote-dns",
        "address": "https://8.8.8.8/dns-query",
        "address_resolver": "direct-dns",
        "strategy": "ipv4_only"
      },
      {
        "tag": "direct-dns",
        "address": "local",
        "strategy": "ipv4_only"
      },
      {
        "tag": "dns-final",
        "address": "local",
        "address_resolver": "dns-local",
        "strategy": "ipv4_only"
      },
      {
        "tag": "dns-local",
        "address": "local"
      },
      {
        "tag": "dns-block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "domain": [
          "8.8.8.8"
        ],
        "server": "direct-dns"
      }
    ],
    "final": "dns-final",
    "independent_cache": true
  },
  "inbounds": [
    {
      "type": "tun",
      "mtu": 1400,
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fdfe:dcba:9876::1/126",
      "auto_route": true,
      "strict_route": true,
      "endpoint_independent_nat": true,
      "stack": "mixed",
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "tag": "Internet",
      "type": "selector",
      "outbounds": [
        "Best Latency",
` : `{
  "outbounds": [
`;
  parsedLinks.forEach((link) => {
    config += `        "${link.name}",
`;
  });
  if (isFullConfig) {
    config += `        "direct"
      ]
    },
    {
      "type": "urltest",
      "tag": "Best Latency",
      "outbounds": [
`;
    parsedLinks.forEach((link) => {
      config += `        "${link.name}",
`;
    });
    config += `        "direct"
      ],
      "url": "https://www.google.com",
      "interval": "10s"
    },
`;
  }
  parsedLinks.forEach((link, index) => {
    if (index > 0) config += ",\n";
    config += `    {
`;
    config += `      "tag": "${link.name}",
`;
    if (link.type === "vmess") {
      config += `      "type": "vmess",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "alter_id": ${link.alterId || 0},
`;
      config += `      "security": "${link.cipher || "zero"}",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "vless") {
      config += `      "type": "vless",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "trojan") {
      config += `      "type": "trojan",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "password": "${link.password}",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "ss") {
      config += `      "type": "shadowsocks",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "method": "${link.cipher || "none"}",
`;
      config += `      "password": "${link.password}",
`;
      config += `      "plugin": "v2ray-plugin",
`;
      config += `      "plugin_opts": "mux=0;path=${link.wsPath};host=${link.wsHost || link.server};tls=${link.tls ? "1" : "0"}"
`;
    }
    config += `    }`;
  });
  if (isFullConfig) {
    config += `,
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "direct",
      "tag": "bypass"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "port": 53,
        "outbound": "dns-out"
      },
      {
        "inbound": "dns-in",
        "outbound": "dns-out"
      },
      {
        "network": "udp",
        "port": 443,
        "outbound": "block"
      },
      {
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "outbound": "block"
      }
    ],
    "auto_detect_interface": true
  },
  "experimental": {
    "cache_file": {
      "enabled": false
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip",
      "external_ui_download_detour": "Internet",
      "secret": "stupid",
      "default_mode": "rule"
    }
  }
}`;
  } else {
    config += `
  ]
}`;
  }
  return config;
}
__name(generateSingboxConfig, "generateSingboxConfig");

// src/converter/converter.js
// src/converter/converter.js
const Converterbot = class {
  static {
    __name(this, "Converterbot");
  }
  constructor(token, apiUrl, ownerId, env) {
    this.token = token;
    this.apiUrl = apiUrl || "https://api.telegram.org";
    this.ownerId = ownerId;
    this.env = env;
  }
  async handleUpdate(update) {
    if (!update.message)
      return new Response("OK", { status: 200 });
    const chatId = update.message.chat.id;
    const text = update.message.text || "";
    const messageId = update.message.message_id;
    if (text.startsWith("/broadcast") && chatId.toString() === this.ownerId.toString()) {
      const broadcastMessage = text.substring("/broadcast ".length).trim();
      if (broadcastMessage) {
        await this.sendBroadcastMessage(broadcastMessage);
      } else {
        await this.sendMessage(chatId, "Contoh penggunaan: `/broadcast Pesan yang ingin Anda siarkan.`");
      }
      return new Response("OK", { status: 200 });
    }
    if (text.startsWith("/converter")) {
      await this.sendMessage(
        chatId,
        ` *Geo Project Bot*

Kirimkan link konfigurasi V2Ray dan saya *SPIDERMAN* akan mengubahnya ke format *Singbox*, *Nekobox*, dan *Clash*.

Contoh:
\`vless://...\`
\`vmess://...\`
\`trojan://...\`
\`ss://...\`

Catatan:
- Maksimal 10 link per permintaan.
- Disarankan menggunakan *Singbox versi 1.10.3* atau *1.11.8*.`,
        { reply_to_message_id: messageId }
      );
      return new Response("OK", { status: 200 });
    }
    if (text.includes("://")) {
      try {
        const links = text.split("\n").map((line) => line.trim()).filter((line) => line.includes("://")).slice(0, 10);
        if (links.length === 0) {
          await this.sendMessage(chatId, " Tidak ada link valid yang ditemukan. Kirimkan link VMess, VLESS, Trojan, atau Shadowsocks.", { reply_to_message_id: messageId });
          return new Response("OK", { status: 200 });
        }
        const clashConfig = generateClashConfig(links, true);
        const nekoboxConfig = generateNekoboxConfig(links, true);
        const singboxConfig = generateSingboxConfig(links, true);
        await this.sendDocument(chatId, clashConfig, "clash.yaml", "text/yaml", { reply_to_message_id: messageId });
        await this.sendDocument(chatId, nekoboxConfig, "nekobox.json", "application/json", { reply_to_message_id: messageId });
        await this.sendDocument(chatId, singboxConfig, "singbox.bpf", "application/json", { reply_to_message_id: messageId });
      } catch (error) {
        console.error("Error processing links:", error);
        await this.sendMessage(chatId, `Error: ${error.message}`, { reply_to_message_id: messageId });
      }
    } else {
    }
    return new Response("OK", { status: 200 });
  }
  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async sendDocument(chatId, content, filename, mimeType, options = {}) {
    const formData = new FormData();
    const blob = new Blob([content], { type: mimeType });
    formData.append("document", blob, filename);
    formData.append("chat_id", chatId.toString());
    if (options.reply_to_message_id) {
      formData.append("reply_to_message_id", options.reply_to_message_id.toString());
    }
    const response = await fetch(
      `${this.apiUrl}/bot${this.token}/sendDocument`,
      {
        method: "POST",
        body: formData
      }
    );
    return response.json();
  }
  async sendBroadcastMessage(message) {
    const userChats = await this.env.GEO_DB.get("broadcast_users", { type: "json" }) || [];
    let successCount = 0;
    let failCount = 0;
    const updatedUsers = [];
    for (const chatId of userChats) {
      try {
        const response = await this.sendMessage(chatId, message);
        if (response.ok) {
          successCount++;
          updatedUsers.push(chatId);
        } else {
          failCount++;
          console.error(`Gagal mengirim pesan ke ${chatId}: ${response.description}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      } catch (error) {
        console.error(`Gagal mengirim pesan ke ${chatId}:`, error);
        failCount++;
      }
    }
    await this.env.GEO_DB.put("broadcast_users", JSON.stringify(updatedUsers));
    const totalUsers = updatedUsers.length;
    const broadcastReport = `Pesan broadcast telah dikirimkan.

Total user terdaftar: *${totalUsers}*
Berhasil dikirim: *${successCount}*
Gagal dikirim: *${failCount}*`;
    await this.sendMessage(this.ownerId, broadcastReport);
  }
};

// src/randomconfig.js
function generateUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
__name(generateUUID, "generateUUID");
async function randomconfig() {
  try {
    const HOSTKU2 = "joss.krikkrik.web.id";
    const GITHUB_BASE_URL = "https://raw.githubusercontent.com/jaka2m/botak/main/cek/";
    const proxyResponse = await fetch(`${GITHUB_BASE_URL}proxyList.txt`);
    if (!proxyResponse.ok) {
      return " Gagal mengambil daftar proxy.";
    }
    const ipText = await proxyResponse.text();
    const ipLines = ipText.split("\n").filter((line) => line.trim() !== "");
    if (ipLines.length === 0) {
      return " Daftar proxy kosong atau tidak valid.";
    }
    const randomIndex = Math.floor(Math.random() * ipLines.length);
    const randomProxyLine = ipLines[randomIndex];
    const sequenceNumber = randomIndex + 1;
    const [ip, port, country, provider] = randomProxyLine.split(",");
    if (!ip || !port) {
      return " Data IP atau Port tidak lengkap dari daftar proxy.";
    }
    const checkResponse = await fetch(`https://geovpn.vercel.app/check?ip=${ip}:${port}`);
    if (!checkResponse.ok) {
      return ` Gagal cek status IP ${ip}:${port}.`;
    }
    const data = await checkResponse.json();
    if (data.status?.toUpperCase() !== "ACTIVE") {
      return ` IP ${ip}:${port} tidak aktif.`;
    }
    const pathIPPORT = `/Free-VPN-CF-Geo-Project/${ip}=${port}`;
    const pathCD = `/Free-VPN-CF-Geo-Project/${data.countryCode}${sequenceNumber}`;
    const toBase642 = /* @__PURE__ */ __name((str) => {
      if (typeof btoa === "function") {
        return btoa(unescape(encodeURIComponent(str)));
      } else if (typeof Buffer !== "undefined") {
        return Buffer.from(str, "utf-8").toString("base64");
      } else {
        return encodeURIComponent(str);
      }
    }, "toBase64");
    const infoMessage = `
IP      : ${data.ip}
PORT    : ${data.port}
ISP     : ${data.isp}
COUNTRY : ${data.country}
DELAY   : ${data.delay}
STATUS  : ${data.status}
`;
    const vlessUUID = generateUUID();
    const trojanUUID = generateUUID();
    const ssPassword = generateUUID();
    const vlessTLSLink1 = `vless://${vlessUUID}@${HOSTKU2}:443?encryption=none&security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathIPPORT)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const trojanTLSLink1 = `trojan://${trojanUUID}@${HOSTKU2}:443?security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathIPPORT)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const ssTLSLink1 = `ss://${toBase642(`none:${ssPassword}`)}@${HOSTKU2}:443?encryption=none&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathIPPORT)}&security=tls&sni=${HOSTKU2}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const vlessTLSLink2 = `vless://${vlessUUID}@${HOSTKU2}:443?encryption=none&security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathCD)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const trojanTLSLink2 = `trojan://${trojanUUID}@${HOSTKU2}:443?security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathCD)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const ssTLSLink2 = `ss://${toBase642(`none:${ssPassword}`)}@${HOSTKU2}:443?encryption=none&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathCD)}&security=tls&sni=${HOSTKU2}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const configText = `
\`\`\`INFORMATION
${infoMessage}
\`\`\`
\`\`\`VLESS-TLS
${vlessTLSLink1}
\`\`\`
\`\`\`TROJAN-TLS
${trojanTLSLink1}
\`\`\`
\`\`\`SHADOWSOCKS-TLS
${ssTLSLink1}
\`\`\`

(Country Code Path : ${data.countryCode}${sequenceNumber})

\`\`\`VLESS-TLS
${vlessTLSLink2}
\`\`\`
\`\`\`TROJAN-TLS
${trojanTLSLink2}
\`\`\`
\`\`\`SHADOWSOCKS-TLS
${ssTLSLink2}
\`\`\`

 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
`;
    return configText;
  } catch (error) {
    console.error("Terjadi kesalahan:", error);
    return ` Terjadi kesalahan: ${error.message}`;
  }
}
__name(randomconfig, "randomconfig");

// src/config.js
async function rotateconfig(chatId, text) {
  const command = text.trim();
  const args = command.split(" ");
  if (args.length !== 2) {
    await this.sendMessage(chatId, ` *Format salah! Gunakan contoh berikut:*
\`/rotate id\``, {
      parse_mode: "Markdown"
    });
    return;
  }
  const countryCode = args[1].toLowerCase();
  const validCountries = [
    "id",
    "sg",
    "my",
    "us",
    "ca",
    "in",
    "gb",
    "ir",
    "ae",
    "fi",
    "tr",
    "md",
    "tw",
    "ch",
    "se",
    "nl",
    "es",
    "ru",
    "ro",
    "pl",
    "al",
    "nz",
    "mx",
    "it",
    "de",
    "fr",
    "am",
    "cy",
    "dk",
    "br",
    "kr",
    "vn",
    "th",
    "hk",
    "cn",
    "jp"
  ];
  if (!validCountries.includes(countryCode)) {
    await this.sendMessage(chatId, ` *Kode negara tidak valid! Gunakan kode yang tersedia.*`, {
      parse_mode: "Markdown"
    });
    return;
  }
  const loadingMessage = await this.sendMessage(chatId, " Sedang memproses config...");
  try {
    const response = await fetch("https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt");
    const ipText = await response.text();
    const ipList = ipText.split("\n").map((line) => line.trim()).filter((line) => line !== "");
    if (ipList.length === 0) {
      await this.sendMessage(chatId, ` *Tidak ada IP untuk negara ${countryCode.toUpperCase()}*`, {
        parse_mode: "Markdown"
      });
      await this.deleteMessage(chatId, loadingMessage.result.message_id);
      return;
    }
    const [ip, port, country, provider] = ipList[Math.floor(Math.random() * ipList.length)].split(",");
    if (!ip || !port) {
      await this.sendMessage(chatId, ` Data IP atau Port tidak lengkap dari daftar proxy.`, {
        parse_mode: "Markdown"
      });
      await this.deleteMessage(chatId, loadingMessage.result.message_id);
      return;
    }
    const statusResponse = await fetch(`https://geovpn.vercel.app/check?ip=${ip}:${port}`);
    const ipData = await statusResponse.json();
    if (ipData.status !== "ACTIVE") {
      await this.sendMessage(chatId, ` *IP ${ip}:${port} tidak aktif.*`, {
        parse_mode: "Markdown"
      });
      await this.deleteMessage(chatId, loadingMessage.result.message_id);
      return;
    }
    const getFlagEmoji3 = /* @__PURE__ */ __name((code) => code.toUpperCase().split("").map((c) => String.fromCodePoint(127462 + c.charCodeAt(0) - 65)).join(""), "getFlagEmoji");
    const generateUUID4 = /* @__PURE__ */ __name(() => "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === "x" ? r : r & 3 | 8;
      return v.toString(16);
    }), "generateUUID");
    const toBase642 = /* @__PURE__ */ __name((str) => typeof btoa === "function" ? btoa(unescape(encodeURIComponent(str))) : Buffer.from(str, "utf-8").toString("base64"), "toBase64");
    const HOSTKU2 = "joss.krikkrik.web.id";
    const path = `/Free-VPN-CF-Geo-Project/${ip}=${port}`;
    const encodedVlessLabelTLS = encodeURIComponent(`ROTATE VLESS ${ipData.isp} ${ipData.country} TLS`);
    const encodedVlessLabelNTLS = encodeURIComponent(`ROTATE VLESS ${ipData.isp} ${ipData.country} NTLS`);
    const encodedTrojanLabelTLS = encodeURIComponent(`ROTATE TROJAN ${ipData.isp} ${ipData.country} TLS`);
    const encodedSsLabelTLS = encodeURIComponent(`ROTATE SHADOWSOCKS ${ipData.isp} ${ipData.country} TLS`);
    const encodedSsLabelNTLS = encodeURIComponent(`ROTATE SHADOWSOCKS ${ipData.isp} ${ipData.country} NTLS`);
    const configText = `
\`\`\`INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${ipData.country}
STATUS  : ${ipData.status}
\`\`\`
 *ROTATE VLESS TLS* 
\`\`\`
vless://${generateUUID4()}@${HOSTKU2}:443?encryption=none&security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(path)}#${encodedVlessLabelTLS}
\`\`\`
 *ROTATE VLESS NTLS* 
\`\`\`
vless://${generateUUID4()}@${HOSTKU2}:80?path=${encodeURIComponent(path)}&security=none&encryption=none&host=${HOSTKU2}&fp=randomized&type=ws&sni=${HOSTKU2}#${encodedVlessLabelNTLS}
\`\`\`
 *ROTATE TROJAN TLS* 
\`\`\`
trojan://${generateUUID4()}@${HOSTKU2}:443?encryption=none&security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(path)}#${encodedTrojanLabelTLS}
\`\`\`
 *ROTATE SS TLS* 
\`\`\`
ss://${toBase642(`none:${generateUUID4()}`)}@${HOSTKU2}:443?encryption=none&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(path)}&security=tls&sni=${HOSTKU2}#${encodedSsLabelTLS}
\`\`\`
 *ROTATE SS NTLS* 
\`\`\`
ss://${toBase642(`none:${generateUUID4()}`)}@${HOSTKU2}:80?encryption=none&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(path)}&security=none&sni=${HOSTKU2}#${encodedSsLabelNTLS}
\`\`\`

 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
`;
    await this.sendMessage(chatId, configText, { parse_mode: "Markdown" });
    await this.deleteMessage(chatId, loadingMessage.result.message_id);
  } catch (error) {
    console.error(error);
    await this.sendMessage(chatId, ` Terjadi kesalahan: ${error.message}`);
    await this.deleteMessage(chatId, loadingMessage.result.message_id);
  }
}
__name(rotateconfig, "rotateconfig");

// src/randomip/randomip.js

let globalIpList = [];
let globalCountryCodes = [];

async function fetchProxyList(url) {
    const response = await fetch(url);
    const ipText = await response.text();
    const ipList = ipText.split("\n")
        .map((line) => line.trim())
        .filter((line) => line !== "");
    return ipList;
}
__name(fetchProxyList, "fetchProxyList");

function getFlagEmoji(code) {
    const OFFSET = 127397;
    return [...code.toUpperCase()]
        .map((c) => String.fromCodePoint(c.charCodeAt(0) + OFFSET))
        .join("");
}
__name(getFlagEmoji, "getFlagEmoji");

function buildCountryButtons(page = 0, pageSize = 15) {
    const start = page * pageSize;
    const end = start + pageSize;
    const pageItems = globalCountryCodes.slice(start, end);
    
    const buttons = pageItems.map((code) => ({
        text: `${getFlagEmoji(code)} ${code}`,
        callback_data: `cc_${code}`
    }));
    
    const inline_keyboard = [];
    for (let i = 0; i < buttons.length; i += 3) {
        inline_keyboard.push(buttons.slice(i, i + 3));
    }
    
    const navButtons = [];
    if (page > 0) {
        navButtons.push({ 
            text: "◀️ Prev", 
            callback_data: `randomip_page_${page - 1}` 
        });
    }
    
    if (end < globalCountryCodes.length) {
        navButtons.push({ 
            text: "Next ▶️", 
            callback_data: `randomip_page_${page + 1}` 
        });
    }
    
    if (navButtons.length) {
        inline_keyboard.push(navButtons);
    }
    
    return { inline_keyboard };
}
__name(buildCountryButtons, "buildCountryButtons");

function generateCountryIPsMessage(ipList, countryCode) {
    const filteredIPs = ipList.filter((line) => line.split(",")[2] === countryCode);
    if (filteredIPs.length === 0) return null;
    
    let msg = `🌍 *Proxy IP untuk negara ${countryCode} ${getFlagEmoji(countryCode)}:*\n\n`;
    
    filteredIPs.slice(0, 20).forEach((line) => {
        const [ip, port, _code, isp] = line.split(",");
        msg += `📍 *IP:PORT* : \`${ip}:${port}\`\n`;
        msg += `🌍 *Country* : ${_code} ${getFlagEmoji(_code)}\n`;
        msg += `💻 *ISP* : ${isp}\n\n`;
    });
    
    return msg;
}
__name(generateCountryIPsMessage, "generateCountryIPsMessage");

async function handleRandomIpCommand(bot, chatId) {
    try {
        globalIpList = await fetchProxyList("https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt");
        
        if (globalIpList.length === 0) {
            await bot.sendMessage(chatId, 
                "❌ *Daftar IP kosong atau tidak ditemukan. Coba lagi nanti.*", 
                { parse_mode: "Markdown" }
            );
            return;
        }
        
        globalCountryCodes = [...new Set(globalIpList.map((line) => line.split(",")[2]))].sort();
        
        const text = "Silakan pilih negara untuk mendapatkan IP random:";
        const reply_markup = buildCountryButtons(0);
        
        await bot.sendMessage(chatId, text, {
            parse_mode: "Markdown",
            reply_markup
        });
        
    } catch (error) {
        await bot.sendMessage(chatId, 
            `⚠️ Gagal mengambil data IP: ${error.message}`
        );
    }
}
__name(handleRandomIpCommand, "handleRandomIpCommand");

async function handleCallbackQuery(bot, callbackQuery) {
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const data = callbackQuery.data;
    
    if (data.startsWith("randomip_page_")) {
        const page = parseInt(data.split("_")[2], 10);
        const keyboard = buildCountryButtons(page);
        
        await bot.editMessageReplyMarkup({
            chat_id: chatId,
            message_id: messageId,
            reply_markup: keyboard
        });
        
        await bot.answerCallbackQuery(callbackQuery.id);
        return;
    }
    
    if (data.startsWith("cc_")) {
        const code = data.split("_")[1];
        const msg = generateCountryIPsMessage(globalIpList, code);
        
        if (!msg) {
            await bot.sendMessage(chatId, 
                `❌ Tidak ditemukan IP untuk negara: ${code}`, 
                { parse_mode: "Markdown" }
            );
        } else {
            await bot.sendMessage(chatId, msg, { parse_mode: "Markdown" });
        }
        
        await bot.answerCallbackQuery(callbackQuery.id);
        return;
    }
}
__name(handleCallbackQuery, "handleCallbackQuery");

// src/randomip/bot2.js

const TelegramBotku = class {
    static {
        __name(this, "TelegramBotku");
    }

    constructor(token, apiUrl = "https://api.telegram.org", ownerId, env) {
        this.token = token;
        this.apiUrl = apiUrl;
        this.ownerId = ownerId;
        this.env = env;
    }

    async handleUpdate(update) {
        if (update.callback_query) {
            const data = update.callback_query.data;
            
            await handleCallbackQuery(this, update.callback_query);
            return new Response("OK", { status: 200 });
        }
        
        if (!update.message) return new Response("OK", { status: 200 });
        
        const chatId = update.message.chat.id;
        const text = update.message.text || "";
        const messageId = update.message.message_id;

        if (text === "/proxy") {
            await handleRandomIpCommand(this, chatId);
            return new Response("OK", { status: 200 });
        }

        if (text === "/menu") {
            const menuText = `
  
╭─── • 𝗚𝗘𝗢 𝗕𝗢𝗧 𝗦𝗘𝗥𝗩𝗘𝗥 • ───╮
│
├─ 🌟 *Fitur Utama*
│  ├─ /proxyip ─ Config acak by Flag
│  ├─ /randomconfig ─ Config acak mix
│  ├─ /converter ─ Convert Akun V2ray
│  └─ /config ─ Config auto-rotate
│
├─ 🛠️ *Tools & Info*
│  ├─ /proxy ─ Generate Proxy IPs
│  ├─ /stats ─ Statistik Penggunaan
│  └─ /findproxy ─ Tutorial Cari Proxy
│
├─ 👤 *Manajemen Wildcard*
│  ├─ /add \\\`[bug]\\\` ─ Tambah Wildcard
│  ├─ /del \\\`[bug]\\\` ─ Hapus Wildcard (Admin)
│  └─ /list ─ Daftar Wildcard
│
├─ 📣 *Admin*
│  └─ /broadcast \\\`[teks]\\\` ─ Kirim Pesan
│
├─ ❤️ *Dukungan*
│  └─ /donate ─ Bantu Kopi Admin
│
╰─── •「 @sampiiiiu 」• ───╯

`;
  await this.sendMessage(chatId, menuText, { parse_mode: "Markdown" });
  return new Response("OK", { status: 200 });
}
    if (text === "/proxyip") {
      await this.handleProxyipCommand(chatId);
      return new Response("OK", { status: 200 });
    }

if (text === "/findproxy") {
  const menuText = `

 *TUTORIAL CARI PROXY* 

 **FOFA (fofa.info)**
 Situs: [en.fofa.info](https://en.fofa.info)
 Kueri pencarian:
\`\`\`query
server=="cloudflare" && is_domain=false && banner="Content-Length: 155" && protocol="http" && org!="CLOUDFLARENET" && country="ID" && asn!="59134"
\`\`\`
 **Catatan:**
- Ubah \`asn="63949"\` untuk ISP tertentu
- Ubah \`country="ID"\` ke kode negara lain
- Tambahkan filter port: \`&& port="443"\`


 **HUNTER.HOW**
 Situs: [hunter.how](https://hunter.how)
 Kueri pencarian:
\`\`\`query
as.org!="Cloudflare London, LLC"&&product.name="CloudFlare"&&header.status_code=="400"&&protocol=="http"&&header.content_length=="655"&&ip.country=="ID"
\`\`\`
 **Catatan:**
- Tambah \`&&as.number="59134"\` untuk filter ASN
- Tambah \`&&ip.port="443"\` untuk fokus ke port 443
- Ubah negara dengan \`ip.country="SG"\`


 **SHODAN.IO**
 Situs: [shodan.io](https://shodan.io)
 Kueri pencarian:
\`\`\`query
product:"Cloudflare" country:"ID"
\`\`\`
 **Catatan:**
- Filter port: \`port:443\`
- Filter provider: \`org:"Akamai"\`


 **ZOOMEYE.HK**
 Situs: [zoomeye.hk](https://zoomeye.hk)
 Kueri pencarian:
\`\`\`query
+app:"Cloudflare" +service:"http" +title:"400 The plain HTTP request was sent to HTTPS port" +country:"Singapore"
\`\`\`
 **Catatan:**
- Tambah \`+asn:59134\` untuk filter ASN
- Spesifikkan port dengan \`+port:"443"\`
- Ubah negara dengan \`+country:"Indonesia"\`


 **BINARYEDGE.IO**
 Situs: [app.binaryedge.io](https://app.binaryedge.io)
 Kueri pencarian:
\`\`\`query
country:ID title:"400 The plain HTTP request was sent to HTTPS port" product:nginx protocol:"tcp" name:http banner:"Server: cloudflare" banner:"CF-RAY: -" NOT asn:209242
\`\`\`
 **Catatan:**
- Hapus \`NOT\` untuk mencari ASN tertentu (\`asn:59134\`)
- Tambah filter port dengan \`port:443\`
- Filter provider: \`as_name:Digitalocean\`


 **CENSYS.IO**
 Situs: [search.censys.io](https://search.censys.io)
 Kueri pencarian dasar:
\`\`\`query
not autonomous_system.name: "CLOUDFLARE*" and services: (software.product: "CloudFlare Load Balancer" and http.response.html_title: "400 The plain HTTP request was sent to HTTPS port") and location.country: "Indonesia"
\`\`\`
 **Catatan:**
- Tambahkan filter port dengan \`and services.port=443\`
- Filter provider: \`autonomous_system.name: "nama_provider"\`


 Untuk mengecek status proxy, kirim hasil pencarian langsung ke bot ini.

 *Modded By:* [Geo Project](https://t.me/sampiiiiu)
`;
  await this.sendMessage(chatId, menuText, { parse_mode: "Markdown" });
  return new Response("OK", { status: 200 });
}

if (text === "/donate") {
    const imageUrl = "https://github.com/jaka1m/project/raw/main/BAYAR.jpg";
    
    try {
        await fetch(`${this.apiUrl}/bot${this.token}/sendPhoto`, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json" 
            },
            body: JSON.stringify({
                chat_id: chatId,
                photo: imageUrl,
                caption: `
💝 *Dukung Pengembangan Bot!* 💝

Bantu kami terus berkembang dengan scan QRIS di atas!

✨ *Fitur yang akan datang:*
• Server yang lebih cepat
• Lebih banyak negara proxy
• Fitur premium eksklusif
• Update rutin dan perbaikan bug

Terima kasih atas dukungannya! 🙏

_— Tim GEO BOT SERVER_
`.trim(),
                parse_mode: "Markdown",
                reply_markup: {
                    inline_keyboard: [
                        [
                            { 
                                text: "🌐 GEO PROJECT", 
                                url: "https://t.me/sampiiiiu" 
                            },
                            { 
                                text: "⭐ Beri Rating", 
                                url: "https://t.me/sampiiiiu" 
                            }
                        ],
                        [
                            { 
                                text: "💬 Channel Update", 
                                url: "https://t.me/sampiiiiu" 
                            }
                        ]
                    ]
                }
            })
        });
        
    } catch (error) {
        console.error("❌ Error sending donation photo:", error);
        // Fallback to text message if image fails
        await this.sendMessage(chatId, 
            `💝 *Dukung Pengembangan Bot!*\n\n` +
            `Bantu kami terus berkembang dengan donasi melalui QRIS.\n\n` +
            `Terima kasih atas dukungannya! 🙏\n\n` +
            `🌐 [GEO PROJECT](https://t.me/sampiiiiu)`,
            { parse_mode: "Markdown" }
        );
    }
    
    return new Response("OK", { status: 200 });
}

    if (text === "/stats") {
    const CLOUDFLARE_API_TOKEN = "Wdkss4h77Dp7gpz1GUNd49dUSVCocVE0wkUgQq4l";
    const CLOUDFLARE_ZONE_ID = "340498f7e72be9e4dcd0cf2f0bcb972c";
    
    const getTenDaysAgoDate = /* @__PURE__ */ __name(() => {
        const d = /* @__PURE__ */ new Date();
        d.setDate(d.getDate() - 10);
        return d.toISOString().split("T")[0];
    }, "getTenDaysAgoDate");

    const tenDaysAgo = getTenDaysAgoDate();

    try {
        // Show loading message
        const loadingMsg = await this.sendMessage(chatId, 
            "📊 *Mengambil data statistik...*", 
            { parse_mode: "Markdown" }
        );

        const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                query: `query {
                    viewer {
                        zones(filter: { zoneTag: "${CLOUDFLARE_ZONE_ID}" }) {
                            httpRequests1dGroups(
                                limit: 10,
                                orderBy: [date_DESC],
                                filter: { date_geq: "${tenDaysAgo}" }
                            ) {
                                sum {
                                    bytes
                                    requests
                                }
                                dimensions {
                                    date
                                }
                            }
                        }
                    }
                }`
            })
        });

        const result = await response.json();
        
        if (!result.data || !result.data.viewer || !result.data.viewer.zones.length) {
            throw new Error("Gagal mengambil data pemakaian dari Cloudflare.");
        }

        const dailyData = result.data.viewer.zones[0].httpRequests1dGroups;
        
        if (dailyData.length === 0) {
            await this.editMessageText(chatId, loadingMsg.message_id,
                "📊 *Tidak ada data pemakaian untuk 10 hari terakhir.*",
                { parse_mode: "Markdown" }
            );
            return new Response("OK", { status: 200 });
        }

        // Calculate totals
        let totalBandwidth = 0;
        let totalRequests = 0;
        
        dailyData.forEach((day) => {
            totalBandwidth += day.sum.bytes;
            totalRequests += day.sum.requests;
        });

        // Format main stats message
        let usageText = `📊 *STATISTIK PENGGUNAAN SERVER*\n\n`;
        usageText += `⏰ **Periode:** 10 Hari Terakhir\n`;
        usageText += `📅 **Dari:** ${tenDaysAgo} hingga ${new Date().toISOString().split('T')[0]}\n\n`;
        
        usageText += `📈 **TOTAL KESELURUHAN:**\n`;
        usageText += `   ┣ 📊 Total Requests: ${totalRequests.toLocaleString()}\n`;
        usageText += `   ┗ 💾 Total Bandwidth: ${(totalBandwidth / 1024 ** 3).toFixed(2)} GB\n\n`;
        
        usageText += `📋 **RINCIAN HARIAN:**\n`;
        usageText += "┌─────────────────────────────────┐\n";

        dailyData.forEach((day, index) => {
            const tanggal = new Date(day.dimensions.date).toLocaleDateString('id-ID', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric'
            });
            
            const totalData = (day.sum.bytes / 1024 ** 3).toFixed(2);
            const totalRequests = day.sum.requests.toLocaleString();
            
            usageText += `│ 📅 ${tanggal}\n`;
            usageText += `│ ├─ 📨 Requests: ${totalRequests}\n`;
            usageText += `│ └─ 💾 Bandwidth: ${totalData} GB\n`;
            
            if (index < dailyData.length - 1) {
                usageText += "│ ───────────────────────────────\n";
            }
        });
        
        usageText += "└─────────────────────────────────┘\n\n";
        
        usageText += `💡 *Info:* Data diperbarui secara real-time dari Cloudflare Analytics`;

        // Delete loading message and send final stats
        await this.deleteMessage(chatId, loadingMsg.message_id);
        await this.sendMessage(chatId, usageText, { 
            parse_mode: "Markdown"
        });

    } catch (error) {
        console.error("❌ Error fetching stats:", error);
        await this.sendMessage(
            chatId,
            `❌ *Gagal mengambil data statistik*\n\n` +
            `_Error:_ \`${error.message}\`\n\n` +
            `Pastikan API token dan Zone ID masih valid.`,
            { parse_mode: "Markdown" }
        );
    }
    
    return new Response("OK", { status: 200 });
}
    
    if (text === "/start") {
  const imageUrl = "https://github.com/jaka8m/BOT-CONVERTER/raw/main/start.png";
  try {
    await fetch(`${this.apiUrl}/bot${this.token}/sendPhoto`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        photo: imageUrl,
        caption: `

                 

 👋 *Selamat Datang di Geo Bot Server!*

Bot ini dapat membantu Anda memeriksa status proxy dan membuat konfigurasi V2Ray.

*Cara Penggunaan:*
1. Kirim alamat IP dan port (opsional, default 443).
2. Tunggu beberapa detik untuk hasilnya.

*Format yang Diterima:*
• \`176.97.78.80\`
• \`176.97.78.80:2053\`

Ketik /menu untuk melihat semua perintah yang tersedia.

⚠️ *Catatan:*
- Jika status proxy *DEAD*, konfigurasi tidak akan dibuat.

🔗 *Tautan Penting:*
🌐 [WEB VPN TUNNEL](https://joss.krikkrik.web.id)
📺 [CHANNEL VPS & Script](https://t.me/testikuy_mang)
👥 [GRUP PHREAKER](https://t.me/+Q1ARd8ZsAuM2xB6-)

`.trim(),
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: " GEO PROJECT", url: "https://t.me/sampiiiiu" }]
          ]
        }
      })
    });
  } catch (error) {
    console.error(error);
  }
  return new Response("OK", { status: 200 });
}
return new Response("OK", { status: 200 });
}
  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = { chat_id: chatId, text, ...options };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async editMessageReplyMarkup({ chat_id, message_id, reply_markup }) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageReplyMarkup`;
    const body = { chat_id, message_id, reply_markup };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async answerCallbackQuery(callbackQueryId) {
    const url = `${this.apiUrl}/bot${this.token}/answerCallbackQuery`;
    const body = { callback_query_id: callbackQueryId };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
    async deleteMessage(chatId, messageId) {
    const url = `${this.apiUrl}/bot${this.token}/deleteMessage`;
    const body = { chat_id: chatId, message_id: messageId };
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }
  async editMessageText(text, { chat_id, message_id }) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = { chat_id, message_id, text, parse_mode: "Markdown" };
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }
  async handleProxyipCommand(chatId) {
    const loadingMessage = await this.sendMessage(chatId, " *Sedang memproses, harap tunggu...*", { parse_mode: "Markdown" });
    try {
      const response = await fetch("https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt");
      const ipText = await response.text();
      const ipList = ipText.split("\n").filter((line) => line.trim() !== "");
      if (ipList.length === 0) {
        await this.editMessageText(` *Daftar IP kosong atau tidak ditemukan. Coba lagi nanti.*`, { chat_id: chatId, message_id: loadingMessage.result.message_id });
        return;
      }
      const countryCodes = [...new Set(ipList.map((line) => line.split(",")[2]))].sort();
      paginationState.set(chatId, { countryCodes, page: 0 });
      const buttons = generateCountryButtons(countryCodes, 0);
      await this.deleteMessage(chatId, loadingMessage.result.message_id);
      await this.sendMessage(chatId, " *Pilih negara:*", {
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: buttons }
      });
    } catch (error) {
      console.error("Error fetching IP list:", error);
      await this.editMessageText(` *Terjadi kesalahan saat mengambil daftar IP: ${error.message}*`, { chat_id: chatId, message_id: loadingMessage.result.message_id });
    }
  }
  async editMessageText(text, { chat_id, message_id, parse_mode, reply_markup }) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = { chat_id, message_id, text, parse_mode, reply_markup };
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }
};

// src/checkip/cek.js
const WILDCARD_MAP = {
  ava: "ava.game.naver.com",
  api: "api.midtrans.com",
  blibli: "business.blibli.com",
  ig: "graph.instagram.com",
  vidio: "quiz.int.vidio.com",
  iflix: "live.iflix.com",
  zoom: "support.zoom.us",
  webex: "blog.webex.com",
  spotify: "investors.spotify.com",
  netflix: "cache.netflix.com",
  viu: "zaintest.vuclip.com",
  ruangguru: "io.ruangguru.com",
  fb: "investor.fb.com",
  bakrie: "bakrie.ac.id"
};
const WILDCARD_OPTIONS = Object.entries(WILDCARD_MAP).map(
  ([value, text]) => ({ text, value })
);
const DEFAULT_HOST = "joss.krikkrik.web.id";
const API_URL = "https://geovpn.vercel.app/check?ip=";
async function fetchIPData(ip, port) {
  try {
    const response = await fetch(`${API_URL}${encodeURIComponent(ip)}:${encodeURIComponent(port)}`);
    if (!response.ok) throw new Error("Gagal mengambil data dari API.");
    return await response.json();
  } catch (error) {
    console.error("Error fetching IP data:", error);
    return null;
  }
}
__name(fetchIPData, "fetchIPData");
function createProtocolInlineKeyboard(ip, port) {
  return {
    inline_keyboard: [
      [
        { text: " VLESS", callback_data: `PROTOCOL|VLESS|${ip}|${port}` },
        { text: " TROJAN", callback_data: `PROTOCOL|TROJAN|${ip}|${port}` }
      ],
      [
        { text: " SHADOWSOCKS", callback_data: `PROTOCOL|SHADOWSOCKS|${ip}|${port}` }
      ]
    ]
  };
}
__name(createProtocolInlineKeyboard, "createProtocolInlineKeyboard");
function createInitialWildcardInlineKeyboard(ip, port, protocol) {
  return {
    inline_keyboard: [
      [
        { text: " NO WILDCARD", callback_data: `NOWILDCARD|${protocol}|${ip}|${port}` },
        { text: " WILDCARD", callback_data: `SHOW_WILDCARD|${protocol}|${ip}|${port}` }
      ],
      [
        { text: " Kembali", callback_data: `BACK|${ip}|${port}` }
      ]
    ]
  };
}
__name(createInitialWildcardInlineKeyboard, "createInitialWildcardInlineKeyboard");
function createWildcardOptionsInlineKeyboard(ip, port, protocol) {
  const buttons = WILDCARD_OPTIONS.map((option, index) => [
    { text: ` ${index + 1}. ${option.text}`, callback_data: `WILDCARD|${protocol}|${ip}|${port}|${option.value}` }
  ]);
  buttons.push([{ text: " Kembali", callback_data: `BACK|${ip}|${port}` }]);
  return { inline_keyboard: buttons };
}
__name(createWildcardOptionsInlineKeyboard, "createWildcardOptionsInlineKeyboard");
function generateUUID2() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
__name(generateUUID2, "generateUUID");
function toBase64(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  return btoa(String.fromCharCode(...new Uint8Array(data.buffer)));
}
__name(toBase64, "toBase64");
function generateConfig(config, protocol, wildcardKey = null) {
  if (!config || !config.ip || !config.port || !config.isp) {
    return "❌ Data tidak valid!";
  }
  const host = wildcardKey ? `${WILDCARD_MAP[wildcardKey]}.${DEFAULT_HOST}` : DEFAULT_HOST;
  const sni = host;
  const uuid = generateUUID2();
  const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${config.ip}=${config.port}`);
  const ispEncoded = encodeURIComponent(config.isp);
  let qrUrl = "";
  if (protocol === "VLESS") {
  const vlessTLS = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${sni}&fp=randomized&type=ws&host=${host}&path=${path}#${ispEncoded}`;
  const vlessNTLS = `vless://${uuid}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#${ispEncoded}`;
  qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(vlessTLS)}&size=400x400`;
  return `
\`\`\`VLESS-TLS
${vlessTLS}
\`\`\`
\`\`\`VLESS-NTLS
${vlessNTLS}
\`\`\`
 [QR Code URL](${qrUrl})
 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
`;
}

if (protocol === "TROJAN") {
  const configString1 = `trojan://${uuid}@${host}:443?security=tls&sni=${sni}&fp=randomized&type=ws&host=${host}&path=${path}#${ispEncoded}`;
  const configString2 = `trojan://${uuid}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#${ispEncoded}`;
  qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=400x400`;
  return `
\`\`\`TROJAN-TLS
${configString1}
\`\`\`
\`\`\`TROJAN-NTLS
${configString2}
\`\`\`
 [QR Code URL](${qrUrl})
 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
`;
}

if (protocol === "SHADOWSOCKS") {
  const configString1 = `ss://${toBase64(`none:${uuid}`)}@${host}:443?encryption=none&type=ws&host=${host}&path=${path}&security=tls&sni=${sni}#${ispEncoded}`;
  const configString2 = `ss://${toBase64(`none:${uuid}`)}@${host}:80?encryption=none&type=ws&host=${host}&path=${path}&security=none&sni=${sni}#${ispEncoded}`;
  qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=400x400`;
  return `
\`\`\`SHADOWSOCKS-TLS
${configString1}
\`\`\`
\`\`\`SHADOWSOCKS-NTLS
${configString2}
\`\`\`
 [QR Code URL](${qrUrl})
 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
`;
}

return " Unknown protocol!";
}
__name(generateConfig, "generateConfig");

// src/checkip/botCek.js
const TelegramProxyCekBot = class {
  static {
    __name(this, "TelegramProxyCekBot");
  }
  constructor(token, apiUrl = "https://api.telegram.org") {
    this.token = token;
    this.apiUrl = apiUrl;
  }
  async sendRequest(method, body) {
    const url = `${this.apiUrl}/bot${this.token}/${method}`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async sendMessage(chatId, text, extra = {}) {
    return this.sendRequest("sendMessage", { chat_id: chatId, text, parse_mode: "Markdown", ...extra });
  }
  async editMessage(chatId, messageId, text, extra = {}) {
    return this.sendRequest("editMessageText", { chat_id: chatId, message_id: messageId, text, parse_mode: "Markdown", ...extra });
  }
  async deleteMessage(chatId, messageId) {
    return this.sendRequest("deleteMessage", { chat_id: chatId, message_id: messageId });
  }
  async sendChatAction(chatId, action = "typing") {
    return this.sendRequest("sendChatAction", { chat_id: chatId, action });
  }
  async handleUpdate(update) {
    if (!update.message && !update.callback_query) return new Response("OK", { status: 200 });
    if (update.message && update.message.text) {
      const chatId = update.message.chat.id;
      const messageId = update.message.message_id;
      const text = update.message.text.trim();
      const ipOnlyMatch = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
      const ipPortMatch = text.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
      if (!ipOnlyMatch && !ipPortMatch) {
        return new Response("OK", { status: 200 });
      }
      const ip = ipPortMatch ? ipPortMatch[1] : ipOnlyMatch[1];
      const port = ipPortMatch ? ipPortMatch[2] : "443";
      await this.deleteMessage(chatId, messageId);
      await this.sendChatAction(chatId, "typing");
      const loadingMsg = await this.sendMessage(chatId, `
\`\`\`Running
Please wait while it is being processed...
\`\`\`
`);
      const data = await fetchIPData(ip, port);
      if (!data) {
        await this.editMessage(chatId, loadingMsg.result.message_id, `❌ Gagal mengambil data untuk IP ${ip}:${port}`);
        return new Response("OK", { status: 200 });
      }
      const { isp, country, delay, status } = data;
      const infoText = `\`\`\`INFORMATION
IP     : ${ip}
PORT   : ${port}
ISP    : ${isp}
Country: ${country || "-"}
Delay  : ${delay || "-"}
Status : ${status || "-"}
\`\`\`
Pilih protokol:`;
      await this.editMessage(chatId, loadingMsg.result.message_id, infoText, {
        reply_markup: createProtocolInlineKeyboard(ip, port)
      });
      return new Response("OK", { status: 200 });
    }
    if (update.callback_query) {
      const callback = update.callback_query;
      const chatId = callback.message.chat.id;
      const messageId = callback.message.message_id;
      const data = callback.data;
      const parts = data.split("|");
      if (parts[0] === "PROTOCOL") {
        const [_, protocol, ip, port] = parts;
        await this.editMessage(chatId, messageId, ` ⚙️Opsi wildcard untuk ${protocol}`, {
          reply_markup: createInitialWildcardInlineKeyboard(ip, port, protocol)
        });
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "SHOW_WILDCARD") {
        const [_, protocol, ip, port] = parts;
        await this.editMessage(chatId, messageId, ` Opsi wildcard untuk ${protocol}`, {
          reply_markup: createWildcardOptionsInlineKeyboard(ip, port, protocol)
        });
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "NOWILDCARD") {
        const [_, protocol, ip, port] = parts;
        await this.sendChatAction(chatId, "typing");
        const loadingMsg = await this.sendMessage(chatId, `
\`\`\`Running
Please wait while it is being processed...
\`\`\`
`);
        const dataInfo = await fetchIPData(ip, port);
        if (!dataInfo) {
          await this.editMessage(chatId, messageId, `❌ Gagal mengambil data untuk IP ${ip}:${port}`);
          await this.deleteMessage(chatId, loadingMsg.result.message_id);
          return new Response("OK", { status: 200 });
        }
        const configText = generateConfig(dataInfo, protocol, null);
        await this.editMessage(chatId, messageId, ` Config ${protocol} NO Wildcard:
${configText}
`, {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [[{
              text: " Back",
              callback_data: `BACK_WILDCARD|${protocol}|${ip}|${port}`
            }]]
          }
        });
        await this.deleteMessage(chatId, loadingMsg.result.message_id);
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "WILDCARD") {
        const [_, protocol, ip, port, wildcardKey] = parts;
        await this.sendChatAction(chatId, "typing");
        const loadingMsg = await this.sendMessage(chatId, `
\`\`\`Running
Please wait while it is being processed...
\`\`\`
`);
        const dataInfo = await fetchIPData(ip, port);
        if (!dataInfo) {
          await this.editMessage(chatId, messageId, `❌ Gagal mengambil data untuk IP ${ip}:${port}`);
          await this.deleteMessage(chatId, loadingMsg.result.message_id);
          return new Response("OK", { status: 200 });
        }
        const configText = generateConfig(dataInfo, protocol, wildcardKey);
        await this.editMessage(chatId, messageId, ` Config ${protocol} Wildcard *${wildcardKey}*:
${configText}
`, {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [[{
              text: " Back",
              callback_data: `BACK_WILDCARD|${protocol}|${ip}|${port}`
            }]]
          }
        });
        await this.deleteMessage(chatId, loadingMsg.result.message_id);
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "BACK") {
        const [_, ip, port] = parts;
        const dataInfo = await fetchIPData(ip, port);
        if (!dataInfo) {
          await this.editMessage(chatId, messageId, `❌ Gagal mengambil data untuk IP ${ip}:${port}`);
          return new Response("OK", { status: 200 });
        }
        const infoText = `\`\`\`INFORMATION
IP     : ${ip}
PORT   : ${port}
ISP    : ${dataInfo.isp}
Country: ${dataInfo.country}
Delay  : ${dataInfo.delay}
Status : ${dataInfo.status}
\`\`\`
Pilih protokol:`;
        await this.editMessage(chatId, messageId, infoText, {
          reply_markup: createProtocolInlineKeyboard(ip, port)
        });
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "BACK_WILDCARD") {
        const [_, protocol, ip, port] = parts;
        await this.editMessage(chatId, messageId, ` Opsi wildcard untuk ${protocol}`, {
          reply_markup: createInitialWildcardInlineKeyboard(ip, port, protocol)
        });
        return new Response("OK", { status: 200 });
      }
      return new Response("OK", { status: 200 });
    }
  }
};

// src/proxyip/proxyip.js
const APIKU = "https://geovpn.vercel.app/check?ip=";
const DEFAULT_HOST2 = "joss.krikkrik.web.id";
const sentMessages = /* @__PURE__ */ new Map();
const paginationState = /* @__PURE__ */ new Map();
function generateUUID3() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0, v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
__name(generateUUID3, "generateUUID");
function getFlagEmoji2(countryCode) {
  if (!countryCode) return "";
  const codePoints = [...countryCode.toUpperCase()].map((c) => 127462 - 65 + c.charCodeAt());
  return String.fromCodePoint(...codePoints);
}
__name(getFlagEmoji2, "getFlagEmoji");
function canSendMessage(chatId, key, interval = 3e4) {
  const now = Date.now();
  if (!sentMessages.has(chatId)) sentMessages.set(chatId, {});
  const userData = sentMessages.get(chatId);
  if (!userData[key] || now - userData[key] > interval) {
    userData[key] = now;
    return true;
  }
  return false;
}
__name(canSendMessage, "canSendMessage");
function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
__name(chunkArray, "chunkArray");
function generateCountryButtons(countryCodes, page = 0, pageSize = 12) {
  const totalPages = Math.ceil(countryCodes.length / pageSize);
  const start = page * pageSize;
  const pageItems = countryCodes.slice(start, start + pageSize);
  const rows = chunkArray(pageItems, 3);
  const buttons = rows.map(
    (row) => row.map((code) => ({
      text: `${getFlagEmoji2(code)} ${code}`,
      callback_data: `select_${code}`
    }))
  );
  const navButtons = [];
if (page > 0) {
  navButtons.push({ text: " Prev", callback_data: `page_prev_${page - 1}` });
}
if (page < totalPages - 1) {
  navButtons.push({ text: "Next ", callback_data: `page_next_${page + 1}` });
}
navButtons.push({ text: " Back", callback_data: `page_back` });
buttons.push(navButtons);
return buttons;
}
__name(generateCountryButtons, "generateCountryButtons");
async function handleCallbackQuery2(bot, callbackQuery) {
  const chatId = callbackQuery.message.chat.id;
  const data = callbackQuery.data;
  if (data.startsWith("page_")) {
    if (!paginationState.has(chatId)) {
      await bot.answerCallbackQuery(callbackQuery.id, { text: "Session expired, silakan ulangi perintah." });
      return;
    }
    const { countryCodes } = paginationState.get(chatId);
    let page = paginationState.get(chatId).page;
    if (data === "page_back") {
      paginationState.delete(chatId);
      await bot.editMessageText(" *Pilih negara:*", {
        chat_id: chatId,
        message_id: callbackQuery.message.message_id,
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: generateCountryButtons(countryCodes, 0) }
      });
      paginationState.set(chatId, { countryCodes, page: 0 });
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    if (data.startsWith("page_prev_")) {
      const newPage = parseInt(data.split("_")[2], 10);
      if (newPage >= 0) {
        page = newPage;
        paginationState.set(chatId, { countryCodes, page });
        const buttons = generateCountryButtons(countryCodes, page);
        await bot.editMessageReplyMarkup({ inline_keyboard: buttons }, {
          chat_id: chatId,
          message_id: callbackQuery.message.message_id
        });
      }
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    if (data.startsWith("page_next_")) {
      const newPage = parseInt(data.split("_")[2], 10);
      const maxPage = Math.ceil(countryCodes.length / 12) - 1;
      if (newPage <= maxPage) {
        page = newPage;
        paginationState.set(chatId, { countryCodes, page });
        const buttons = generateCountryButtons(countryCodes, page);
        await bot.editMessageReplyMarkup({ inline_keyboard: buttons }, {
          chat_id: chatId,
          message_id: callbackQuery.message.message_id
        });
      }
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
  }
  if (data.startsWith("select_")) {
    if (!canSendMessage(chatId, `select_${data}`)) {
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    const countryCode = data.split("_")[1];
    try {
      const response = await fetch("https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt");
      const ipText = await response.text();
      const ipList = ipText.split("\n").filter((line) => line.trim() !== "");
      const filteredIPs = ipList.filter((line) => line.split(",")[2] === countryCode);
      if (filteredIPs.length === 0) {
        await bot.sendMessage(chatId, ` *Tidak ada IP tersedia untuk negara ${countryCode}.*`, { parse_mode: "Markdown" });
        await bot.answerCallbackQuery(callbackQuery.id);
        return;
      }
      const randomProxy = filteredIPs[Math.floor(Math.random() * filteredIPs.length)];
      const [ip, port, , provider] = randomProxy.split(",");
      const statusResponse = await fetch(`${APIKU}${ip}:${port}`);
      const ipData = await statusResponse.json();
      const status = ipData.status === "ACTIVE" ? " ACTIVE" : " DEAD";
      const safeProvider = provider.replace(/[^a-zA-Z0-9]/g, "").slice(0, 10);
      const buttons = [
        [
          { text: " VLESS", callback_data: `config_vless_${ip}_${port}_${countryCode}_${safeProvider}` },
          { text: " TROJAN", callback_data: `config_trojan_${ip}_${port}_${countryCode}_${safeProvider}` }
        ],
        [
          { text: " SHADOWSOCKS", callback_data: `config_ss_${ip}_${port}_${countryCode}_${safeProvider}` }
        ]
      ];
      let messageText = ` *Info IP untuk ${getFlagEmoji2(countryCode)} ${countryCode} :*
\`\`\`
INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${ipData.country}
STATUS  : ${status}
\`\`\``;
      if (ipData.latitude && ipData.longitude) {
        messageText += `
  [View Google Maps](https://www.google.com/maps?q=${ipData.latitude},${ipData.longitude})`;
      }
      await bot.sendMessage(chatId, messageText, {
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: buttons }
      });
    } catch (error) {
  console.error(" Error fetching IP status:", error);
  await bot.sendMessage(chatId, ` *Terjadi kesalahan saat memverifikasi IP.*`, { parse_mode: "Markdown" });
}
    await bot.answerCallbackQuery(callbackQuery.id);
    return;
  }
  if (data.startsWith("config_")) {
    if (!canSendMessage(chatId, `config_${data}`)) {
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    try {
      const [_, type, ip, port, countryCode, provider] = data.split("_");
      const uuid = generateUUID3();
      const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${ip}=${port}`);
      const prov = encodeURIComponent(`${provider} ${getFlagEmoji2(countryCode)}`);
      const toBase642 = /* @__PURE__ */ __name((str) => btoa(unescape(encodeURIComponent(str))), "toBase64");
      let configText = "";
      if (type === "vless") {
        configText = `\`\`\`VLESS-TLS
vless://${uuid}@${DEFAULT_HOST2}:443?encryption=none&security=tls&sni=${DEFAULT_HOST2}&fp=randomized&type=ws&host=${DEFAULT_HOST2}&path=${path}#${prov}
\`\`\`\`\`\`VLESS-NTLS
vless://${uuid}@${DEFAULT_HOST2}:80?path=${path}&security=none&encryption=none&host=${DEFAULT_HOST2}&fp=randomized&type=ws&sni=${DEFAULT_HOST2}#${prov}
\`\`\``;
      } else if (type === "trojan") {
        configText = `\`\`\`TROJAN-TLS
trojan://${uuid}@${DEFAULT_HOST2}:443?encryption=none&security=tls&sni=${DEFAULT_HOST2}&fp=randomized&type=ws&host=${DEFAULT_HOST2}&path=${path}#${prov}
\`\`\`\`\`\`TROJAN-NTLS
trojan://${uuid}@${DEFAULT_HOST2}:80?path=${path}&security=none&encryption=none&host=${DEFAULT_HOST2}&fp=randomized&type=ws&sni=${DEFAULT_HOST2}#${prov}
\`\`\``;
      } else if (type === "ss") {
        configText = `\`\`\`SHADOWSOCKS-TLS
ss://${toBase642(`none:${uuid}`)}@${DEFAULT_HOST2}:443?encryption=none&type=ws&host=${DEFAULT_HOST2}&path=${path}&security=tls&sni=${DEFAULT_HOST2}#${prov}
\`\`\`\`\`\`SHADOWSOCKS-NTLS
ss://${toBase642(`none:${uuid}`)}@${DEFAULT_HOST2}:80?encryption=none&type=ws&host=${DEFAULT_HOST2}&path=${path}&security=none&sni=${DEFAULT_HOST2}#${prov}
\`\`\``;
      }
      await bot.sendMessage(chatId, configText, { parse_mode: "Markdown" });
    } catch (err) {
      console.error(" Error generating config:", err);
      await bot.sendMessage(chatId, ` *Gagal membuat konfigurasi.*`, { parse_mode: "Markdown" });
    }
    await bot.answerCallbackQuery(callbackQuery.id);
    return;
  }
  await bot.answerCallbackQuery(callbackQuery.id);
}
__name(handleCallbackQuery2, "handleCallbackQuery");

// src/proxyip/bot3.js
const TelegramProxyBot = class {
  static {
    __name(this, "TelegramProxyBot");
  }
  constructor(token, apiUrl = "https://api.telegram.org") {
    this.token = token;
    this.apiUrl = apiUrl;
  }
  async handleUpdate(update) {
    if (update.message) {
      const msg = update.message;
      if (msg.text && msg.text.startsWith("/proxyip")) {
        await handleProxyipCommand(this, msg);
      }
    }
    if (update.callback_query) {
      await handleCallbackQuery2(this, update.callback_query);
    }
    return new Response("OK", { status: 200 });
  }
  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = { chat_id: chatId, text, ...options };
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return res.json();
  }
  async answerCallbackQuery(callbackQueryId, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/answerCallbackQuery`;
    const body = { callback_query_id: callbackQueryId, ...options };
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return res.json();
  }
  async editMessageReplyMarkup(replyMarkup, { chat_id, message_id }) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageReplyMarkup`;
    const body = {
      chat_id,
      message_id,
      reply_markup: replyMarkup
    };
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return res.json();
  }
};

// src/wildcard/botwild.js
const KonstantaGlobalbot = class {
  static {
    __name(this, "KonstantaGlobalbot");
  }
  constructor({ apiKey, rootDomain, accountID, zoneID, apiEmail, serviceName }) {
    this.apiKey = apiKey;
    this.rootDomain = rootDomain;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.serviceName = serviceName;
    this.headers = {
      "Authorization": `Bearer ${this.apiKey}`,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
      "Content-Type": "application/json"
    };
  }
  escapeMarkdownV2(text) {
    return text.replace(/([_*\[\]()~`>#+=|{}.!\\-])/g, "\\$1");
  }
  // Cloudflare API: ambil daftar domain Workers
  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, { headers: this.headers });
    if (!res.ok) return [];
    const json = await res.json();
    return json.result.filter((d) => d.service === this.serviceName).map((d) => d.hostname);
  }
  // Cloudflare API: tambahkan subdomain
  async addSubdomain(subdomain) {
    const domain = `${subdomain}.${this.rootDomain}`.toLowerCase();
    if (!domain.endsWith(this.rootDomain)) return 400;
    const registered = await this.getDomainList();
    if (registered.includes(domain)) return 409;
    try {
      const testRes = await fetch(`https://${subdomain}`);
      if (testRes.status === 530) return 530;
    } catch {
      return 400;
    }
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const body = {
      environment: "production",
      hostname: domain,
      service: this.serviceName,
      zone_id: this.zoneID
    };
    const res = await fetch(url, {
      method: "PUT",
      headers: this.headers,
      body: JSON.stringify(body)
    });
    return res.status;
  }
  // Cloudflare API: hapus subdomain
  async deleteSubdomain(subdomain) {
    const domain = `${subdomain}.${this.rootDomain}`.toLowerCase();
    const listUrl = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const listRes = await fetch(listUrl, { headers: this.headers });
    if (!listRes.ok) return listRes.status;
    const json = await listRes.json();
    const obj = json.result.find((d) => d.hostname === domain);
    if (!obj) return 404;
    const res = await fetch(`${listUrl}/${obj.id}`, {
      method: "DELETE",
      headers: this.headers
    });
    return res.status;
  }
  saveDomainRequest(request) {
    globalThis.subdomainRequests.push(request);
  }
  findPendingRequest(subdomain, requesterId = null) {
    return globalThis.subdomainRequests.find(
      (r) => r.subdomain === subdomain && r.status === "pending" && (requesterId === null || r.requesterId === requesterId)
    );
  }
  updateRequestStatus(subdomain, status) {
    const r = globalThis.subdomainRequests.find(
      (r2) => r2.subdomain === subdomain && r2.status === "pending"
    );
    if (r) r.status = status;
  }
  getAllRequests() {
    return globalThis.subdomainRequests.slice();
  }
};
const TelegramWildcardBot = class {
  static {
    __name(this, "TelegramWildcardBot");
  }
  constructor(token, apiUrl, ownerId, globalBot) {
    this.token = token;
    this.apiUrl = apiUrl || "https://api.telegram.org";
    this.ownerId = ownerId;
    this.globalBot = globalBot;
    this.awaitingAddList = {};
    this.awaitingDeleteList = {};
    this.handleUpdate = this.handleUpdate.bind(this);
  }
  escapeMarkdownV2(text) {
    return this.globalBot.escapeMarkdownV2(text);
  }
  async handleUpdate(update) {
    if (!update.message) return new Response("OK", { status: 200 });
    const chatId = update.message.chat.id;
    const from = update.message.from;
    const username = from.username || from.first_name || "Unknown";
    const text = update.message.text || "";
    const isOwner = chatId === this.ownerId;
    const now = (/* @__PURE__ */ new Date()).toLocaleString("id-ID", { timeZone: "Asia/Jakarta" });
    if (text.startsWith("/add")) {
      const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
      const firstLine = lines[0];
      const restLines = lines.slice(1);
      let subdomains = [];
      if (firstLine.includes(" ") && restLines.length === 0) {
        subdomains = firstLine.split(" ").slice(1).map((s) => s.trim()).filter(Boolean);
      } else if (restLines.length > 0) {
        subdomains = restLines;
      }
      if (subdomains.length === 0) {
        await this.sendMessage(
          chatId,
          "``` \nMohon sertakan satu atau lebih subdomain setelah /add.\n```",
          { parse_mode: "Markdown" }
        );
        return new Response("OK", { status: 200 });
      }
      const results = [];
      for (const sd of subdomains) {
        const cleanSd = sd.trim();
        const full = `${cleanSd}.${this.globalBot.rootDomain}`;
        let st = 500;
        try {
          st = await this.globalBot.addSubdomain(cleanSd);
        } catch {
        }
        results.push(
          st === 200 ? "```-Wildcard\n" + full + " berhasil ditambahkan.```" : ` Gagal menambahkan domain *${full}*, status: ${st}`
        );
      }
      await this.sendMessage(chatId, results.join("\n\n"), { parse_mode: "Markdown" });
      return new Response("OK", { status: 200 });
    }
    if (text.startsWith("/del")) {
      if (!isOwner) {
        await this.sendMessage(chatId, " Anda tidak berwenang menggunakan perintah ini.");
        return new Response("OK", { status: 200 });
      }
      if (text === "/del") {
        this.awaitingDeleteList[chatId] = true;
        await this.sendMessage(
          chatId,
          `\`\`\`Contoh
📝 Silakan kirim daftar subdomain yang ingin dihapus (satu per baris).

/del
ava.game.naver.com
zaintest.vuclip.com
support.zoom.us
\`\`\``,
          { parse_mode: "MarkdownV2" }
        );
        return new Response("OK", { status: 200 });
      }
      const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
      const firstLine = lines[0];
      const restLines = lines.slice(1);
      let toDelete = [];
      if (firstLine.includes(" ") && restLines.length === 0) {
        toDelete = firstLine.split(" ").slice(1).map((s) => s.trim()).filter(Boolean);
      } else if (restLines.length > 0) {
        toDelete = restLines;
      }
      if (toDelete.length === 0) {
        await this.sendMessage(chatId, " Mohon sertakan satu atau lebih subdomain setelah /del.");
        return new Response("OK", { status: 200 });
      }
      const results = [];
      for (const raw of toDelete) {
        let d = raw.toLowerCase().trim();
        let sd;
        if (d.endsWith(`.${this.globalBot.rootDomain}`)) {
          sd = d.slice(0, d.lastIndexOf(`.${this.globalBot.rootDomain}`));
        } else {
          sd = d;
        }
        const full = `${sd}.${this.globalBot.rootDomain}`;
        let st = 500;
        try {
          st = await this.globalBot.deleteSubdomain(sd);
        } catch {
        }
        if (st === 200) results.push(`\`\`\`Wildcard
${full}deleted successfully.\`\`\``);
        else if (st === 404) results.push(` Domain *${full}* tidak ditemukan.`);
        else results.push(` Gagal menghapus domain *${full}*, status: ${st}.`);
      }
      await this.sendMessage(chatId, results.join("\n\n"), { parse_mode: "Markdown" });
      return new Response("OK", { status: 200 });
    }
    if (text.startsWith("/list")) {
      let domains = [];
      try {
        domains = await this.globalBot.getDomainList();
      } catch {
      }
      if (!domains.length) {
        await this.sendMessage(chatId, "*No subdomains registered yet.*", { parse_mode: "MarkdownV2" });
      } else {
        const listText = domains.map(
          (d, i) => `${i + 1}\\. \`${this.escapeMarkdownV2(d)}\``
          // Hanya domain yang di-backtick
        ).join("\n");
        await this.sendMessage(
          chatId,
          ` LIST CUSTOM DOMAIN :

${listText}

 Total: *${domains.length}* subdomain${domains.length > 1 ? "s" : ""}`,
          { parse_mode: "MarkdownV2" }
        );
        const fileContent = domains.map((d, i) => `${i + 1}. ${d}`).join("\n");
        await this.sendDocument(chatId, fileContent, "wildcard-list.txt", "text/plain");
      }
      return new Response("OK", { status: 200 });
    }
    if (text.startsWith("/approve ")) {
      if (!isOwner) {
        await this.sendMessage(chatId, `
\`\`\`
 Anda tidak berwenang menggunakan perintah ini.
\`\`\`
`);
        return new Response("OK", { status: 200 });
      }
      const sd = text.split(" ")[1]?.trim();
      if (!sd) return new Response("OK", { status: 200 });
      const full = `${sd}.${this.globalBot.rootDomain}`;
      const req = this.globalBot.findPendingRequest(sd);
      if (!req) {
        await this.sendMessage(chatId, ` Tidak ada request pending untuk subdomain *${full}*.`, { parse_mode: "Markdown" });
      } else {
        let st = 500;
        try {
          st = await this.globalBot.addSubdomain(sd);
        } catch {
        }
        if (st === 200) {
          this.globalBot.updateRequestStatus(sd, "approved");
          await this.sendMessage(chatId, `\`\`\`
 Wildcard ${full} disetujui dan ditambahkan.
\`\`\``, { parse_mode: "Markdown" });
          await this.sendMessage(req.requesterId, `\`\`\`
 Permintaan Wildcard ${full} Anda telah disetujui pada:
${now}
\`\`\``, { parse_mode: "Markdown" });
        } else {
          await this.sendMessage(chatId, ` Gagal menambahkan domain *${full}*, status: ${st}`, { parse_mode: "Markdown" });
        }
      }
      return new Response("OK", { status: 200 });
    }
    if (text.startsWith("/reject ")) {
      if (!isOwner) {
        await this.sendMessage(chatId, "```\n Anda tidak berwenang menggunakan perintah ini.\n```");
        return new Response("OK", { status: 200 });
      }
      const sd = text.split(" ")[1]?.trim();
      if (!sd) return new Response("OK", { status: 200 });
      const full = `${sd}.${this.globalBot.rootDomain}`;
      const req = this.globalBot.findPendingRequest(sd);
      if (!req) {
        await this.sendMessage(chatId, ` Tidak ada request pending untuk subdomain *${full}*.`, { parse_mode: "Markdown" });
      } else {
        this.globalBot.updateRequestStatus(sd, "rejected");
        await this.sendMessage(
          chatId,
          "```\n Wildcard " + full + " telah ditolak.\n```",
          { parse_mode: "Markdown" }
        );
        await this.sendMessage(
          req.requesterId,
          "```\n Permintaan Wildcard " + full + " Anda telah ditolak pada:\n" + now + "\n```",
          { parse_mode: "Markdown" }
        );
      }
      return new Response("OK", { status: 200 });
    }
    if (text.startsWith("/req")) {
      if (!isOwner) {
        await this.sendMessage(chatId, " Anda tidak berwenang melihat daftar request.", { parse_mode: "MarkdownV2" });
        return new Response("OK", { status: 200 });
      }
      const all = this.globalBot.getAllRequests();
      if (!all.length) {
        await this.sendMessage(chatId, " Belum ada request subdomain masuk.", { parse_mode: "MarkdownV2" });
      } else {
        let lines = "";
        all.forEach((r, i) => {
          const domain = this.escapeMarkdownV2(r.domain);
          const status = this.escapeMarkdownV2(r.status);
          const requester = this.escapeMarkdownV2(r.requesterUsername);
          const requesterId = this.escapeMarkdownV2(r.requesterId.toString());
          const time = this.escapeMarkdownV2(r.requestTime);
          lines += `*${i + 1}\\. ${domain}* — _${status}_
`;
          lines += `   requester: @${requester} \\(ID: ${requesterId}\\)
`;
          lines += `   waktu: ${time}

`;
        });
        const message = ` *Daftar Semua Request:*

${lines}`;
        await this.sendMessage(chatId, message, { parse_mode: "MarkdownV2" });
      }
      return new Response("OK", { status: 200 });
    }
    return new Response("OK", { status: 200 });
  }
  async sendMessage(chatId, text, options = {}) {
    const payload = { chat_id: chatId, text, ...options };
    await fetch(`${this.apiUrl}/bot${this.token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  }
  async sendDocument(chatId, content, filename, mimeType) {
    const formData = new FormData();
    formData.append("chat_id", chatId.toString());
    formData.append("document", new Blob([content], { type: mimeType }), filename);
    await fetch(`${this.apiUrl}/bot${this.token}/sendDocument`, {
      method: "POST",
      body: formData
    });
  }
};

// src/bot.js
const HOSTKU = "joss.krikkrik.web.id";
const TelegramBot = class {
  static {
    __name(this, "TelegramBot");
  }
  constructor(token, apiUrl, ownerId, globalBot) {
    this.token = token;
    this.apiUrl = apiUrl || "https://api.telegram.org";
    this.ownerId = ownerId;
    this.globalBot = globalBot;
  }
  async handleUpdate(update) {
    if (!update.message && !update.callback_query) {
      return new Response("OK", { status: 200 });
    }
    if (update.callback_query) {
      const { message, data } = update.callback_query;
      const chatId = message.chat.id;
      const messageId = message.message_id;
      return new Response("OK", { status: 200 });
    }
    if (update.message) {
      const { chat, text: messageText } = update.message;
      const chatId = chat.id;
      const text = messageText?.trim() || "";
      if (text.startsWith("/config")) {
        const helpMsg = ` *PANDUAN CONFIG ROTATE* 

Ketik perintah berikut untuk mendapatkan config rotate berdasarkan negara:

\`rotate + kode_negara\`

Negara tersedia:
id, sg, my, us, ca, in, gb, ir, ae, fi, tr, md, tw, ch, se, nl, es, ru, ro, pl, al, nz, mx, it, de, fr, am, cy, dk, br, kr, vn, th, hk, cn, jp.

Contoh:
\`rotate id\`
\`rotate sg\`
\`rotate my\`

Bot akan memilih IP secara acak dari negara tersebut dan mengirimkan config-nya.`;
        await this.sendMessage(chatId, helpMsg, { parse_mode: "Markdown" });
        return new Response("OK", { status: 200 });
      }
      if (text.startsWith("rotate ")) {
        await rotateconfig.call(this, chatId, text);
        return new Response("OK", { status: 200 });
      }
      if (text.startsWith("/randomconfig")) {
  const loadingMsg = await this.sendMessageWithDelete(chatId, " Membuat konfigurasi acak...");
  try {
    const configText = await randomconfig();
    await this.sendMessage(chatId, configText, { parse_mode: "Markdown" });
  } catch (error) {
    console.error("Error generating random config:", error);
    await this.sendMessage(chatId, ` Terjadi kesalahan:\n${error.message}`);
  }
  if (loadingMsg && loadingMsg.message_id) {
    await this.deleteMessage(chatId, loadingMsg.message_id);
  }
  return new Response("OK", { status: 200 });
}

if (text.startsWith("/listwildcard")) {
  const wildcards = await this.globalBot.getDomainList();
  const configText = `* LIST WILDCARD *


` + wildcards.map((d, i) => `*${i + 1}.* \`${d}\``).join("\n") + `

 *Total:* ${wildcards.length} wildcard

 *Modded By:* [Geo Project](https://t.me/sampiiiiu)`;
  
  await this.sendMessage(chatId, configText, { parse_mode: "Markdown" });
  return new Response("OK", { status: 200 });
}
}
}
  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async editMessage(chatId, messageId, text, replyMarkup) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = {
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: "Markdown"
    };
    if (replyMarkup) {
      body.reply_markup = replyMarkup;
    }
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async sendMessageWithDelete(chatId, text) {
    try {
      const res = await this.sendMessage(chatId, text);
      return res.result;
    } catch (e) {
      console.error("Gagal mengirim pesan:", e);
      return null;
    }
  }
  async deleteMessage(chatId, messageId) {
    const url = `${this.apiUrl}/bot${this.token}/deleteMessage`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId
      })
    });
    return res.json();
  }
};

// src/kuota.js
const CekkuotaBotku = class _CekkuotaBotku {
  static {
    __name(this, "CekkuotaBotku");
  }
  constructor(token, apiUrl = "https://api.telegram.org") {
    this.token = token;
    this.apiUrl = apiUrl;
    this.baseUrl = `${this.apiUrl}/bot${this.token}`;
  }

  async sendMessage(chatId, text, options = {}) {
    const url = `${this.baseUrl}/sendMessage`;
    const body = {
      chat_id: chatId,
      text,
      ...options
    };
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      if (!res.ok) throw new Error(`Telegram API error: ${res.status}`);
      return res.json();
    } catch (err) {
      console.error(`[ERROR] Send message:`, err.message);
      return null;
    }
  }

  async deleteMessage(chatId, messageId) {
    const url = `${this.baseUrl}/deleteMessage`;
    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: chatId, message_id: messageId })
      });
    } catch (err) {
      console.error(`[ERROR] Delete message:`, err.message);
    }
  }

  async sendChatAction(chatId, action) {
    const url = `${this.baseUrl}/sendChatAction`;
    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: chatId, action })
      });
    } catch (err) {
      console.error(`[ERROR] Send chat action:`, err.message);
    }
  }

  // SOLUSI: Gunakan API yang sama tapi dengan approach berbeda
  async checkQuota(msisdn) {
    // Coba format nomor yang berbeda
    const numbersToTry = [
      msisdn,
      msisdn.startsWith('62') ? '0' + msisdn.substring(2) : msisdn,
      msisdn.startsWith('0') ? '62' + msisdn.substring(1) : msisdn
    ];

    for (const num of numbersToTry) {
      try {
        console.log(`[TRY] Attempting with number: ${num}`);
        const result = await this._makeRequest(num);
        if (result) return result;
      } catch (err) {
        console.log(`[FAIL] Failed with ${num}:`, err.message);
        continue;
      }
    }
    
    throw new Error('Semua format nomor gagal');
  }

  async _makeRequest(msisdn) {
    const url = `https://apigw.kmsp-store.com/sidompul/v4/cek_kuota?msisdn=${msisdn}&isJSON=true`;
    
    // Buat request dengan fetch options yang minimal
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 detik timeout
    
    try {
      const res = await fetch(url, {
        method: "GET",
        headers: {
          'Authorization': 'Basic c2lkb21wdWxhcGk6YXBpZ3drbXNw',
          'X-API-Key': '60ef29aa-a648-4668-90ae-20951ef90c55', 
          'X-App-Version': '4.0.0',
          'Accept': 'application/json',
          'User-Agent': 'Mozilla/5.0 (compatible; Bot)'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      console.log(`[RESPONSE] Status: ${res.status}`);
      
      if (res.status === 403) {
        throw new Error('Akses ditolak oleh server (403)');
      }
      
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      
      const data = await res.json();
      console.log(`[DATA] Response:`, data);
      
      if (data.status === true) {
        return data;
      } else {
        throw new Error(data.message || 'Response tidak valid');
      }
      
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error('Timeout - Server tidak merespons');
      }
      throw err;
    }
  }

  // SOLUSI ALTERNATIF: Jika tetap gagal, berikan template response
  _createFallbackResponse(msisdn) {
    return {
      status: true,
      data: {
        msisdn: msisdn,
        hasil: ` RESULT: <br><br>MSISDN: ${msisdn}<br><br> <b>API sedang tidak dapat diakses</b><br><br> <b>Solusi:</b><br>� Coba lagi nanti<br>� Gunakan website resmi<br>� Pastikan nomor aktif<br><br> <i>Powered by Geo Project</i>`
      }
    };
  }

  _formatResult(hasil) {
    if (!hasil) return " Data tidak tersedia";
    
    let cleaned = hasil
      .replace(/<br>/g, '\n')
      .replace(/<br\/>/g, '\n')
      .replace(/<\/?[^>]+(>|$)/g, '')
      .replace(/\\ud83d\\udcc3/g, '')
      .replace(/\\u274c/g, '')
      .replace(/\\u2705/g, '')
      .replace(/\\ud83c\\udf81/g, '')
      .replace(/\\ud83c\\udf42/g, '')
      .replace(/\\ud83c\\udf32/g, '');
    
    cleaned = cleaned
      .replace(/RESULT:/g, ' HASIL CEK KUOTA:')
      .replace(/MSISDN:/g, ' NOMOR:')
      .replace(/Tipe Kartu:/g, ' TIPE KARTU:')
      .replace(/Status Volte Device:/g, ' VOLTE DEVICE:')
      .replace(/Status Volte Area:/g, ' VOLTE AREA:')
      .replace(/Status Volte Simcard:/g, ' VOLTE SIMCARD:')
      .replace(/Status 4G:/g, ' STATUS 4G:')
      .replace(/Status Dukcapil:/g, ' DUKCAPIL:')
      .replace(/Umur Kartu:/g, ' UMUR KARTU:')
      .replace(/Masa Aktif:/g, ' MASA AKTIF:')
      .replace(/Masa Berakhir Tenggang:/g, ' MASA TENGGANG:')
      .replace(/Quota:/g, ' PAKET:')
      .replace(/Aktif Hingga:/g, ' BERLAKU HINGGA:')
      .replace(/Benefit:/g, ' BENEFIT:')
      .replace(/Tipe Kuota:/g, ' TIPE KUOTA:')
      .replace(/Kuota:/g, ' TOTAL KUOTA:')
      .replace(/Sisa Kuota:/g, ' SISA KUOTA:');
    
    return cleaned;
  }

  async handleUpdate(update) {
    const msg = update.message;
    const chatId = msg?.chat?.id;
    const messageId = msg?.message_id;
    const text = msg?.text?.trim() || "";
    const from = msg?.from || {};
    const username = from.username || from.first_name || "User";
    
    if (!chatId || !text) return;

    if (text.startsWith("/help") || text.startsWith("/start")) {
      const helpText = `
 <b>BOT CEK KUOTA XL</b>

 <b>Cara Penggunaan:</b>
Kirim nomor HP XL untuk cek kuota

 <b>Format:</b>
<code>08xxxxxx</code> atau <code>628xxxxxx</code>

 <b>Contoh:</b>
<code>081234567890</code>
<code>087812345678</code>

 <b>Note:</b>
� Hanya untuk nomor XL
� Jika gagal, coba beberapa saat lagi
      `;
      return this.sendMessage(chatId, helpText, { parse_mode: "HTML" });
    }

    const phoneNumbers = text.split(/\s+/).filter((num) => {
      const cleanNum = num.replace(/[^\d]/g, '');
      return (cleanNum.startsWith("08") || cleanNum.startsWith("628")) && cleanNum.length >= 10 && cleanNum.length <= 14;
    }).map(num => num.replace(/[^\d]/g, ''));
    
    if (phoneNumbers.length === 0) {
      return this.sendMessage(chatId, " Format nomor tidak valid. Gunakan /help untuk bantuan.", { parse_mode: "HTML" });
    }

    const loadingMessage = await this.sendMessage(chatId, ` Memproses ${phoneNumbers.length} nomor...`);
    const loadingMessageId = loadingMessage?.result?.message_id;
    
    await this.sendChatAction(chatId, "typing");
    
    const allResponses = [];
    
    for (const number of phoneNumbers) {
      try {
        console.log(`[PROCESS] Number: ${number}`);
        
        let apiRes;
        try {
          apiRes = await this.checkQuota(number);
        } catch (error) {
          console.log(`[FALLBACK] Using fallback for ${number}`);
          apiRes = this._createFallbackResponse(number);
        }
        
        if (apiRes.status && apiRes.data) {
          const formattedResult = this._formatResult(apiRes.data.hasil);
          allResponses.push(` <b>User:</b> ${username}\n${formattedResult}`);
        } else {
          allResponses.push(` <b>Gagal untuk ${number}:</b>\n${apiRes.data?.keteranganError || apiRes.message || "Error tidak diketahui"}`);
        }
        
      } catch (err) {
        console.error(`[FINAL ERROR] ${number}:`, err.message);
        allResponses.push(` <b>Error untuk ${number}:</b>\n${err.message}\n\n <i>Server API sedang maintenance</i>`);
      }
    }
    
    if (loadingMessageId) {
      await this.deleteMessage(chatId, loadingMessageId);
    }
    
    if (allResponses.length > 0) {
      await this.sendMessage(chatId, allResponses.join("\n\n"), { parse_mode: "HTML" });
    }
    
    if (messageId) {
      await this.deleteMessage(chatId, messageId);
    }
  }
};

// src/worker.js
const worker_default = {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    try {
      const update = await request.json();
      if (update.message) {
        const chatId = update.message.chat.id;
        const currentUsers = await env.GEO_DB.get("broadcast_users", { type: "json" }) || [];
        if (!currentUsers.includes(chatId)) {
          currentUsers.push(chatId);
          await env.GEO_DB.put("broadcast_users", JSON.stringify(currentUsers));
        }
      }
      const token = "8260084773:AAG3eaP0FbYg7FizqSeAre8GHcCOOSv1oUc";
      const ownerId = 1467883032;
      const apiKey = "28595cd826561d8014059ca54712d3ca3332c";
      const accountID = "716746bfb7638b3aaa909b55740fbc60";
      const zoneID = "340498f7e72be9e4dcd0cf2f0bcb972c";
      const apiEmail = "pihajamal@gmail.com";
      const serviceName = "joss";
      const rootDomain = "krikkrik.web.id";
      const globalBot = new KonstantaGlobalbot({
        apiKey,
        accountID,
        zoneID,
        apiEmail,
        serviceName,
        rootDomain
      });
      let bot;
      if (update.callback_query) {
        const data = update.callback_query.data;
        if (data.startsWith("randomip_page_") || data.startsWith("cc_")) {
          bot = new TelegramBotku(token, "https://api.telegram.org", ownerId, env);
        } else if (data.startsWith("PROTOCOL|") || data.startsWith("SHOW_WILDCARD|") || data.startsWith("NOWILDCARD|") || data.startsWith("WILDCARD|") || data.startsWith("BACK|") || data.startsWith("BACK_WILDCARD|")) {
          bot = new TelegramProxyCekBot(token, "https://api.telegram.org", ownerId, globalBot);
        } else if (data.startsWith("page_") || data.startsWith("select_") || data.startsWith("config_")) {
          bot = new TelegramProxyBot(token, "https://api.telegram.org", ownerId, globalBot);
        }
      } else if (update.message && update.message.text) {
        const text = update.message.text.trim();
        if (text.startsWith("/config") || text.startsWith("rotate ") || text.startsWith("/randomconfig") || text.startsWith("/listwildcard")) {
          bot = new TelegramBot(token, "https://api.telegram.org", ownerId, globalBot);
        } else if (text.startsWith("/proxy") || text.startsWith("/menu") || text.startsWith("/findproxy") || text.startsWith("/donate") || text.startsWith("/stats") || text.startsWith("/start") || text.startsWith("/proxyip")) {
          bot = new TelegramBotku(token, "https://api.telegram.org", ownerId, env);
        } else if (text.match(/^(\d{1,3}(?:\.\d{1,3}){3}):?(\d{1,5})?$/) && !text.includes("://")) {
          bot = new TelegramProxyCekBot(token, "https://api.telegram.org", ownerId, globalBot);
        } else if (text.startsWith("/add") || text.startsWith("/del") || text.startsWith("/list") || text.startsWith("/approve ") || text.startsWith("/reject ") || text.startsWith("/req")) {
          bot = new TelegramWildcardBot(token, "https://api.telegram.org", ownerId, globalBot);
        } else if (text.startsWith("/help") || text.split(/\s+/).some((num) => (num.startsWith("08") || num.startsWith("628")) && num.length >= 10 && num.length <= 14)) {
          bot = new CekkuotaBotku(token, "https://api.telegram.org", ownerId, globalBot);
        } else if (text.startsWith("/broadcast") || text.startsWith("/converter") || text.includes("://")) {
          bot = new Converterbot(token, "https://api.telegram.org", ownerId, env);
        }
      }
      if (bot) {
        await bot.handleUpdate(update);
      }
      return new Response("OK", { status: 200 });
    } catch (error) {
      return new Response(
        JSON.stringify({ error: error.message }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }
};
export {
  worker_default as default
};
