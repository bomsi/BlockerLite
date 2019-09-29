# Copyright (c) 2018 Mislav Bozicevic
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IProxyListener
from java.io import PrintWriter
import sys

#
# Simple Burp extension to drop blacklisted hosts
#
class BurpExtender(IBurpExtender, IExtensionStateListener, IProxyListener):
	
	#
	# implement IBurpExtender
	#
	
	def registerExtenderCallbacks(self, callbacks):
		# main entry point for the extension
		
		# set our extension name
		callbacks.setExtensionName('BlockerLite')
		
		# register ourselves as extension state listener (IExtensionStateListener)
		callbacks.registerExtensionStateListener(self)
		
		# register ourselves as proxy listener (IProxyListener)
		callbacks.registerProxyListener(self)
		
		# keep a reference to our callbacks object
		self._callbacks = callbacks
		
		# get output streams in auto-flush mode
		self._stdout = PrintWriter(callbacks.getStdout(), True)
		self._stderr = PrintWriter(callbacks.getStderr(), True)
		
		# create and populate the blacklist
		self._blacklist = set()
		self._blacklist.add('http://ciscobinary.openh264.org')
		self._blacklist.add('http://detectportal.firefox.com')
		self._blacklist.add('https://location.services.mozilla.com')
		self._blacklist.add('https://activity-stream-icons.services.mozilla.com')
		self._blacklist.add('https://shavar.services.mozilla.com')
		self._blacklist.add('https://versioncheck-bg.addons.mozilla.org')
		self._blacklist.add('https://snippets.cdn.mozilla.net')
		self._blacklist.add('https://getpocket.com')
		self._blacklist.add('https://safebrowsing.googleapis.com')
		self._blacklist.add('https://tiles.services.mozilla.com')
		self._blacklist.add('https://incoming.telemetry.mozilla.org')
		self._blacklist.add('https://services.addons.mozilla.org')
		self._blacklist.add('https://aus5.mozilla.org')
		self._blacklist.add('https://normandy.cdn.mozilla.net')
		self._blacklist.add('https://blocklists.settings.services.mozilla.com')
		self._blacklist.add('https://firefox.settings.services.mozilla.com')
		self._blacklist.add('https://redirector.gvt1.com')
		self._blacklist.add('https://push.services.mozilla.com')
		self._blacklist.add('https://content-signature-2.cdn.mozilla.net')
		
		self._stdout.println('Extension was loaded')
		self._stdout.println('Running under version ' + sys.version)
		
		return
	
	#
	# implement IExtensionStateListener
	#
	
	def extensionUnloaded(self):
		self._blacklist.clear()
		self._stdout.println('Extension was unloaded.')
		
		return
	
	#
	# implement IProxyListener
	#
	
	def processProxyMessage(self, messageIsRequest, message):
		message_type = 'request to ' if messageIsRequest else 'response from '
		host = message.getMessageInfo().getHttpService().toString()
		
		# if host is in the blacklist, message will be dropped
		drop = host in self._blacklist
		
		self._stdout.println('Proxy ' + message_type + host +
			(' dropped' if drop else ' not dropped.'))
		
		if drop == True:
			message.setInterceptAction(message.ACTION_DROP)
		
		return
