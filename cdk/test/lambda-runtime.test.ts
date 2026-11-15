// Guards Node2Shell (CVE-2026-111497): no Lambda may use an EOL Node runtime (nodejs20.x and older
// never receive the Brotli fix). Covers both the synthesized stack and the shipped template.
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { QBusinessCodeAnalysisStack } from '../lib/q-business-code-analysis-stack';

const EOL_NODE = /^nodejs(1[0-9]|20)\.x$/;

test('shipped assets/cloudformation.yml has no EOL Node runtimes', () => {
  const text = fs.readFileSync(path.join(__dirname, '../../assets/cloudformation.yml'), 'utf8');
  const runtimes = [...text.matchAll(/^\s*Runtime:\s*(\S+)\s*$/gm)].map((m) => m[1]);
  expect(runtimes.length).toBeGreaterThan(0);
  expect(runtimes.filter((r) => EOL_NODE.test(r))).toEqual([]);
});

test('synthesized stack has no EOL Node runtimes', () => {
  const app = new cdk.App();
  const stack = new QBusinessCodeAnalysisStack(app, 'TestStack', {
    env: { account: '111122223333', region: 'us-east-1' },
  });
  const fns = Object.values(Template.fromStack(stack).findResources('AWS::Lambda::Function'));
  expect(fns.length).toBeGreaterThan(0);
  for (const fn of fns) {
    expect((fn as any).Properties.Runtime).not.toMatch(EOL_NODE);
  }
});
