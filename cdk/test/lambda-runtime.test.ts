// Guards Node2Shell (CVE-2026-111497): no Lambda may use an EOL Node runtime (nodejs20.x and older
// never receive the Brotli fix). Covers both the synthesized stack and the shipped template.
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { QBusinessCodeAnalysisStack } from '../lib/q-business-code-analysis-stack';

// Allowlist: any nodejs* runtime must be a patched one, so old/odd identifiers (nodejs8.10, quoted values) fail closed.
const isUnpatchedNode = (rt: string) => rt.startsWith('nodejs') && !/^nodejs(22|24|26)\.x$/.test(rt);

test('shipped assets/cloudformation.yml has no EOL Node runtimes', () => {
  const text = fs.readFileSync(path.join(__dirname, '../../assets/cloudformation.yml'), 'utf8');
  const runtimes = [...text.matchAll(/^\s*Runtime:\s*(\S+)\s*$/gm)].map((m) => m[1].replace(/["']/g, ''));
  expect(runtimes.length).toBeGreaterThan(0);
  expect(runtimes.filter(isUnpatchedNode)).toEqual([]);
});

test('synthesized stack has no EOL Node runtimes', () => {
  const app = new cdk.App();
  const stack = new QBusinessCodeAnalysisStack(app, 'TestStack', {
    env: { account: '111122223333', region: 'us-east-1' },
  });
  const fns = Object.values(Template.fromStack(stack).findResources('AWS::Lambda::Function'));
  expect(fns.length).toBeGreaterThan(0);
  for (const fn of fns) {
    expect(isUnpatchedNode((fn as any).Properties.Runtime)).toBe(false);
  }
});
