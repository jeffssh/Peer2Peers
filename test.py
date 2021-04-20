#!/usr/bin/env python3

import time
from progress.bar import Bar

bar = Bar('Downloading and verifying pieces', max=100)
for _ in range(20):
	time.sleep(1)
	bar.next()
