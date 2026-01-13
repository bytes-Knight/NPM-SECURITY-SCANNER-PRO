
// Mock Config
const CONFIG = {
    NODE_BUILTINS: new Set(['fs', 'path', 'http'])
};

class PackageNameExtractor {
    static extract(importPath) {
        if (!importPath || typeof importPath !== 'string') return null;

        // 1. Handle CDN URLs (Simplified mock for test)
        if (importPath.includes('unpkg.com')) {
            return importPath.split('/')[3].split('@')[0];
        }

        // 2. Standard Import Path Cleaning
        importPath = importPath
            .replace(/^(https?:\/\/|node:|file:)/, '')
            .replace(/^\//, '')
            .replace(/^(\.\.\/)*node_modules\//, '');

        if (importPath.startsWith('.')) return null;

        const parts = importPath.split('/');

        // Handle scoped packages (@org/package)
        if (importPath.startsWith('@')) {
            // If the part has a version attached like @scope/pkg@1.2.3, we need to handle it
            // But first, let's just take the first two parts as the potential name
            // Actually, the split('/') above might separate @scope and pkg if it was @scope/pkg
            // But if it was @scope/pkg@1.2.3, parts[0] is @scope, parts[1] is pkg@1.2.3
            // So we need to reconstruct and then strip.

            // Let's look at how the original code does it:
            // const parts = importPath.split('/');
            // if (importPath.startsWith('@')) return parts.length > 1 ? `${parts[0]}/${parts[1]}` : null;

            // So for @scope/pkg@1.2.3, parts is ['@scope', 'pkg@1.2.3']
            // It returns '@scope/pkg@1.2.3'
        }

        // Let's simulate the logic in content.js exactly

        let pkgName = parts[0];
        if (importPath.startsWith('@')) {
            pkgName = parts.length > 1 ? `${parts[0]}/${parts[1]}` : null;
        }

        // Filter built-ins and invalid names
        if (!pkgName || CONFIG.NODE_BUILTINS.has(pkgName)) return null;

        // Strip version if present
        if (pkgName.startsWith('@')) {
            // Scoped package: @scope/pkg@1.2.3
            const parts = pkgName.slice(1).split('@'); // Remove first @ then split
            if (parts.length > 1) {
                pkgName = '@' + parts[0];
            }
        } else if (pkgName.includes('@')) {
            // Regular package: pkg@1.2.3
            pkgName = pkgName.split('@')[0];
        }

        if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(pkgName)) return null;

        return pkgName;
    }
}

// Test Cases
const tests = [
    { input: 'react', expected: 'react' },
    { input: 'react@18.2.0', expected: 'react' },
    { input: '@scope/pkg', expected: '@scope/pkg' },
    { input: '@scope/pkg@1.2.3', expected: '@scope/pkg' },
    { input: 'fs', expected: null },
    { input: './local', expected: null },
    { input: 'lodash/fp', expected: 'lodash' },
    { input: 'libs/my-lib@2.0.0', expected: 'libs' },
];

console.log('Running PackageNameExtractor Tests...');
let passed = 0;
tests.forEach(t => {
    const result = PackageNameExtractor.extract(t.input);
    if (result === t.expected) {
        console.log(`PASS: ${t.input} -> ${result}`);
        passed++;
    } else {
        console.error(`FAIL: ${t.input} -> Expected ${t.expected}, got ${result}`);
    }
});

console.log(`\n${passed}/${tests.length} tests passed.`);
