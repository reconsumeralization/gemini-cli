$content = Get-Content packages/cli/src/ui/hooks/vim.test.ts -Raw

# Replace patterns with both sequence and name
$content = $content -replace "\{ sequence: '([^']+)', name: '([^']+)' \}", "createKey('$1', '$2')"

# Replace patterns with just sequence
$content = $content -replace "\{ sequence: '([^']+)' \}", "createKey('$1')"

# Replace patterns with sequence and ctrl
$content = $content -replace "\{ sequence: '([^']+)', ctrl: (true|false) \}", "createKey('$1', undefined, `$2)"

# Replace patterns with name and ctrl
$content = $content -replace "\{ name: '([^']+)', ctrl: (true|false) \}", "createKey('$1', '$1', `$2)"

Set-Content packages/cli/src/ui/hooks/vim.test.ts $content
