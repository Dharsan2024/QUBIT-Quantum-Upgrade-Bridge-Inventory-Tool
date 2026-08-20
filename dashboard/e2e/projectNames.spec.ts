import { expect, test } from '@playwright/test';

import { projectNameForTargets } from '../src/lib/projectNames';

/**
 * Unit tests for the function that decides which project a scan lands in.
 *
 * This runs under the browser suite's runner but needs no browser — same arrangement as
 * `assertions.spec.ts`, and for the same reason: the function is pure, and the interesting cases
 * are string shapes rather than anything on screen.
 *
 * It matters more than a naming helper usually would. Before it existed, every scan started from
 * the app was filed under one project called "Dashboard scans"; on the development machine that
 * single project had accumulated ten unrelated scans and 872 assets — two source trees, a git
 * remote and three probes of 127.0.0.1, all rendered as one inventory. The target strings below
 * are the real ones from that database, not invented examples.
 *
 * The Windows cases are the ones worth pinning. The separator is a backslash, which is also the
 * escape character in a regex, in a JS string literal, in a shell heredoc and in a Python
 * replacement string — and it was silently dropped by two of those layers while this was being
 * written, leaving a `[\/]` character class that matched only forward slashes and turned every
 * Windows path into one unsplit project name. `SEP` is built from a char code so no quoting layer
 * between here and the assertion can eat it.
 */

/** A literal backslash, immune to every quoting layer between this file and the regex. */
const SEP = String.fromCharCode(92);

test.describe('projectNameForTargets', () => {
  test('names a filesystem scan after the directory being scanned', () => {
    expect(
      projectNameForTargets([`X:${SEP}final yaer${SEP}main projects${SEP}demo-lab${SEP}medivault-emr`]),
    ).toBe('medivault-emr');
    expect(projectNameForTargets(['X:/final yaer/main projects/demo-lab/vulnapp-python'])).toBe(
      'vulnapp-python',
    );
    expect(projectNameForTargets(['demo-lab/skyline-edge'])).toBe('skyline-edge');
    expect(projectNameForTargets(['/samples'])).toBe('samples');
  });

  test('ignores a trailing separator rather than producing an empty name', () => {
    expect(projectNameForTargets([`X:${SEP}relyce${SEP}billingversion1${SEP}`])).toBe(
      'billingversion1',
    );
    expect(projectNameForTargets(['demo-lab/skyline-edge/'])).toBe('skyline-edge');
  });

  test('names a git remote after the repository, without the .git suffix', () => {
    expect(projectNameForTargets(['https://github.com/OpenVPN/easy-rsa.git'])).toBe('easy-rsa');
    expect(projectNameForTargets(['git@github.com:org/some-repo.git'])).toBe('some-repo');
  });

  test('counts the remainder when several targets are scanned together', () => {
    expect(projectNameForTargets([`X:${SEP}a`, `X:${SEP}b`, `X:${SEP}c`])).toBe('a +2');
    expect(projectNameForTargets(['10.0.0.5', '10.0.0.6'], 'network')).toBe('10.0.0.5 +1');
  });

  test('names network and Vault scans after the host, not a path segment', () => {
    expect(projectNameForTargets(['127.0.0.1'], 'network')).toBe('127.0.0.1');
    expect(projectNameForTargets(['https://tls.example.com/'], 'network')).toBe('tls.example.com');
    expect(projectNameForTargets(['http://127.0.0.1:8200'], 'vault')).toBe('Vault 127.0.0.1:8200');
  });

  test('never returns an empty name', () => {
    // An empty name would be rejected by the API and would surface as a failed scan rather than
    // as the naming problem it actually is.
    for (const targets of [[], [''], ['   '], [`X:${SEP}`], ['/'], ['//']]) {
      expect(projectNameForTargets(targets).trim().length).toBeGreaterThan(0);
    }
  });

  test('is stable, so rescanning the same target reuses its project', () => {
    // This is what gives a project a scan history instead of minting a new project per scan.
    const target = `X:${SEP}final yaer${SEP}main projects${SEP}demo-lab${SEP}helm-ops`;
    expect(projectNameForTargets([target])).toBe(projectNameForTargets([target]));
    expect(projectNameForTargets([target])).toBe(projectNameForTargets([`${target}${SEP}`]));
  });
});
