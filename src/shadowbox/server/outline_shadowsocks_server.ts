// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as child_process from 'child_process';
import * as jsyaml from 'js-yaml';
import * as mkdirp from 'mkdirp';
import * as path from 'path';
import * as https from 'https';
import { SocksProxyAgent } from 'socks-proxy-agent'; // 引入 SOCKS5 代理模块

import * as file from '../infrastructure/file';
import * as logging from '../infrastructure/logging';
import {ShadowsocksAccessKey, ShadowsocksServer} from '../model/shadowsocks_server';

// Runs outline-ss-server.
export class OutlineShadowsocksServer implements ShadowsocksServer {
  private ssProcess: child_process.ChildProcess;
  private ipCountryFilename?: string;
  private ipAsnFilename?: string;
  private isAsnMetricsEnabled = false;
  private isReplayProtectionEnabled = false;
  
  // 定义代理地址和端口
  private proxyAgent = new SocksProxyAgent('socks5h://127.0.0.1:40000');

  constructor(
    private readonly binaryFilename: string,
    private readonly configFilename: string,
    private readonly verbose: boolean,
    private readonly metricsLocation: string
  ) {}

  configureCountryMetrics(ipCountryFilename: string): OutlineShadowsocksServer {
    this.ipCountryFilename = ipCountryFilename;
    return this;
  }

  configureAsnMetrics(ipAsnFilename: string): OutlineShadowsocksServer {
    this.ipAsnFilename = ipAsnFilename;
    return this;
  }

  enableReplayProtection(): OutlineShadowsocksServer {
    this.isReplayProtectionEnabled = true;
    return this;
  }

  update(keys: ShadowsocksAccessKey[]): Promise<void> {
    return this.writeConfigFile(keys).then(() => {
      if (!this.ssProcess) {
        this.start();
        return Promise.resolve();
      } else {
        this.ssProcess.kill('SIGHUP');
      }
    });
  }

  private writeConfigFile(keys: ShadowsocksAccessKey[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const keysJson = {keys: [] as ShadowsocksAccessKey[]};
      for (const key of keys) {
        if (!isAeadCipher(key.cipher)) {
          logging.error(
            `Cipher ${key.cipher} for access key ${key.id} is not supported: use an AEAD cipher instead.`
          );
          continue;
        }

        keysJson.keys.push(key);
      }

      mkdirp.sync(path.dirname(this.configFilename));

      try {
        file.atomicWriteFileSync(this.configFilename, jsyaml.safeDump(keysJson, {sortKeys: true}));
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  }

  // Method to check if the proxy is functioning
  private checkProxyConnection() {
    const options = {
      hostname: 'ipinfo.io',
      port: 443,
      path: '/json',
      method: 'GET',
      agent: this.proxyAgent
    };

    const req = https.request(options, (res) => {
      logging.info(`Proxy Check Status: ${res.statusCode}`);
      res.on('data', (d) => {
        process.stdout.write(d); // Log the proxy check response (IP details)
      });
    });

    req.on('error', (e) => {
      logging.error(`Proxy connection failed: ${e.message}`);
    });

    req.end();
  }

  private start() {
    logging.info('Starting Shadowsocks service with proxy...');

    // Check if the proxy is working before starting the service
    //this.checkProxyConnection();

    const commandArguments = ['-config', this.configFilename, '-metrics', this.metricsLocation];
    if (this.ipCountryFilename) {
      commandArguments.push('-ip_country_db', this.ipCountryFilename);
    }
    if (this.ipAsnFilename) {
      commandArguments.push('-ip_asn_db', this.ipAsnFilename);
    }
    if (this.verbose) {
      commandArguments.push('-verbose');
    }
    if (this.isReplayProtectionEnabled) {
      commandArguments.push('--replay_history=10000');
    }

    logging.info('======== Starting Outline Shadowsocks Service ========');
    logging.info(`${this.binaryFilename} ${commandArguments.map((a) => `"${a}"`).join(' ')}`);

    logging.info(`Full environment: ${JSON.stringify(process.env)}`);
    logging.info(`ALL_PROXY is set to: ${process.env.ALL_PROXY}`);

    // 通过 SOCKS5 代理启动 Shadowsocks 服务
    this.ssProcess = child_process.spawn(this.binaryFilename, commandArguments, {
      env: {
        ...process.env
      }
    });

    this.ssProcess.on('error', (error) => {
      logging.error(`Error spawning outline-ss-server: ${error}`);
    });

    this.ssProcess.on('exit', (code, signal) => {
      logging.info(`outline-ss-server has exited with error. Code: ${code}, Signal: ${signal}`);
      logging.info('Restarting');
      this.start();
    });

    this.ssProcess.stdout.on('data', (data) => {
      logging.info(`Shadowsocks stdout: ${data}`);
    });

    this.ssProcess.stderr.on('data', (data) => {
      logging.error(`Shadowsocks stderr: ${data}`);
    });

    this.ssProcess.stdout.pipe(process.stdout);
    this.ssProcess.stderr.pipe(process.stderr);
  }
}

// List of AEAD ciphers can be found at https://shadowsocks.org/en/spec/AEAD-Ciphers.html
function isAeadCipher(cipherAlias: string) {
  cipherAlias = cipherAlias.toLowerCase();
  return cipherAlias.endsWith('gcm') || cipherAlias.endsWith('poly1305');
}
