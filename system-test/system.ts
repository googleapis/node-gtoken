/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import * as assert from 'assert';
import {describe, it} from 'mocha';
import {GoogleToken} from '../src';
import {copyFileSync, readFileSync} from 'fs';

// gtoken requires a file extension to determine key type:
const keyFile = './key-file.json';
copyFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS!, keyFile);

describe('gtoken system tests', () => {
  it('should acquire an access token', async () => {
    const gtoken = new GoogleToken({
      keyFile,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
    });
    const token = await gtoken.getToken();
    assert.ok(token.access_token);
  });

  it('should acquire an id token', async () => {
    const keys = JSON.parse(readFileSync(keyFile, 'utf8'));
    const gtoken = new GoogleToken({
      keyFile,
      additionalClaims: {
        target_audience: keys.client_id,
      },
    });
    const token = await gtoken.getToken();
    assert.ok(token.id_token);
  });
});
