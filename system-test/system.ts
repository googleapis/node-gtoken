/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import * as assert from 'assert';
import {GoogleToken} from '../src';

describe('gtoken system tests', () => {
  it('should acquire an access token', async () => {
    const gtoken = new GoogleToken({
      keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
    });
    const token = await gtoken.getToken();
    assert.ok(token.access_token);
  });

  it('should acquire an id token', async () => {
    const keys = require(process.env.GOOGLE_APPLICATION_CREDENTIALS!);
    const gtoken = new GoogleToken({
      keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
      additionalClaims: {
        target_audience: keys.client_id,
      },
    });
    const token = await gtoken.getToken();
    assert.ok(token.id_token);
  });
});
