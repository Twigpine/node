#!/usr/bin/env node
// The git remote helper, as `git-remote-twigpine` and `git-remote-gitlawb`.
// Git picks the helper by URL scheme and talks to it over stdin and stdout,
// which pass straight through.
import { run } from './launch.js';

run('git-remote-twigpine', 'git-remote-twigpine');
