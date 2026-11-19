#!/usr/bin/env node
// `gl`, the command's name before the rename. The program sees itself started
// as `gl` and prints a one-line note about the new name on a terminal.
import { run } from './launch.js';

run('twigpine', 'gl');
