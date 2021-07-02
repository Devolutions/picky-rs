#!/bin/sh

PRE_COMMIT_HOOK=./.git/hooks/pre-commit

if test -f "$PRE_COMMIT_HOOK"; then
	echo "$(tput setaf 1)$PRE_COMMIT_HOOK already exists"
	exit 1
fi

echo "#!/bin/sh
git stash -q --keep-index

ret=0

cargo +stable fmt --all -- --check 2> /dev/null

if ! [ \$? -eq 0 ] ; then
    ret=1
    printf \"\n\$(tput setaf 3)Bad formatting, please run 'cargo +stable fmt' and stage modifications\n\n\"
fi

cargo clippy -- -D warnings

if ! [ \$? -eq 0 ] ; then
    ret=1
    printf \"\n\$(tput setaf 3)Fix clippy lints and stage modifications\n\n\"
fi

if ! [ \$ret -eq 0 ] ; then
    printf \"\$(tput setaf 1)Git pre-commit hook failed.\$(tput sgr0)\n\"
    printf \"Alternatively, \\\`--no-verify\\\` or \\\`-n\\\` option may be used to bypass the pre-commit hook.\n\"
fi

git stash pop -q

exit \$ret" > "$PRE_COMMIT_HOOK"
chmod +x "$PRE_COMMIT_HOOK"
echo "$(tput setaf 2)$PRE_COMMIT_HOOK created"

