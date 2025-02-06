// Copyright 2019 Google LLC
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

import {describe, it} from 'mocha';
import {packNTest} from 'pack-n-play';

/**
 * Optionally keep the staging directory between tests.
 */

describe('pack-n-play', () => {
  it('supports ESM', async () => {
    await packNTest({
      sample: {
        description: 'import as ESM',
        esm: `
          import {GoogleToken} from 'gtoken';
        
          async function main() {
            const gtoken = new GoogleToken();
          }
          main();
          `,
      },
    });
  });

  it('supports CJS', async () => {
    await packNTest({
      sample: {
        description: 'require as CJS',
        cjs: `
          const {GoogleToken} = require('gtoken');
          async function main() {
            const gtoken = new GoogleToken();
          }
          main();
          `,
      },
    });
  });

  it('TypeScript', async function () {
    this.timeout(300000);
    await packNTest({
      packageDir: process.cwd(),
      sample: {
        description: 'TypeScript user can use the type definitions',
        ts: `
            import {GoogleToken} from 'gtoken';
            async function main() {
               const gtoken = new GoogleToken();
            }
            main();
           `,
      },
    });
  });
});
