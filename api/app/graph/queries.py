# The graph-traversal queries (blast radius, vendor breach cascade,
# framework coverage, etc.) now live in the private `graphrisk-core`
# package -- see https://github.com/munenesimon/graphrisk-core.
# Render installs it during build (see the Build Command in Settings ->
# Build & Deploy); locally, run `pip install -e ../../graphrisk-core`
# (or wherever you've cloned it) to develop against it.
from graphrisk_core.queries import *  # noqa: F401,F403
