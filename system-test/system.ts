/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import * as assert from 'assert';

import {GoogleToken} from '../src';

describe('gtoken system tests', () => {
  const gtoken = new GoogleToken({
    keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
  });

  it('should acquire a token', async () => {
    const token = await gtoken.getToken();
    assert.ok(token);
  });
});
