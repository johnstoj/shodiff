#!/usr/bin/env python

import argparse
import colorama
import os
import shodan
import sys
import datetime

from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship, sessionmaker, backref
from sqlalchemy.ext.declarative import declarative_base

# ##############################################################################
Base = declarative_base()

class ShodanSearch(Base):
  __tablename__ = u'shodan_search'
  id = Column(Integer, primary_key=True)
  hosts = relationship(u'Host', 
                       backref=u'shodan_search',
                       cascade="all, delete-orphan")

  string = Column(String)
  timestamp = Column(DateTime, default=datetime.datetime.now)

  def __str__(self):
    as_string = u''
    
    for host in self.hosts:
      as_string += self.string + u' ' + host.ip
      
      for port in host.ports:
        as_string += u' ' + str(port.number)

      as_string += u'\n'

    return u'\n'.join(sorted(as_string.splitlines()))

  def host_count(self):
    return len(self.hosts)


class Host(Base):
  __tablename__ = u'host'
  id = Column(Integer, primary_key=True)
  search_term_id = Column(Integer, ForeignKey(ShodanSearch.id))
  ports = relationship(u'Port',
                       backref=u'host',
                       cascade="all, delete-orphan")

  ip = Column(String)
  hostname = Column(String, default=u'')    # FIXME: Hosts can have multilpe names.

  def __eq__(self, other):
    if self.ip != other.ip:
      return False

    if len(self.ports) != len(other.ports):
      return False

    for port in self.ports:
      if port not in other.ports:
        return False

    return True


class Port(Base):
  __tablename__ = u'port'
  id = Column(Integer, primary_key=True)
  host_id = Column(Integer, ForeignKey(Host.id))

  number = Column(Integer)
  # FIXME: Add protocol.

  def __eq__(self, other):
    return self.number == other.number


# ##############################################################################
class Shodan():
  def __init__(self, api_key=os.environ[str(u'SHODAN_API_TOKEN')]):
    self.api = shodan.Shodan(api_key)

  def _host_ips_from_raw_result(self, raw_search_results):
    hosts = set()
    for result in raw_search_results[u'matches']:
      hosts.add(result[u'ip_str'])

    return list(hosts)

  def search(self, search_term):
    raw_search_results = self.api.search(search_term)

    search_result = ShodanSearch(string=search_term)
    
    ips = sorted(self._host_ips_from_raw_result(raw_search_results))
    for ip in ips:
      host = Host(ip=ip)
      search_result.hosts.append(host)

      raw_host_info = self.api.host(ip)
      ports = raw_host_info[u'ports']
      for port in ports:
        host.ports.append(Port(number=port))

    return search_result

class ShodanCache():
  def __init__(self):
    self.db_engine = create_engine(u'sqlite:///shodiff_cache.db')
    Session = sessionmaker()
    Session.configure(bind=self.db_engine)
    Base.metadata.create_all(self.db_engine)

    self.session = Session()

  def search(self, thing):
    cached_search = None
    thing = thing.string if type(thing) is ShodanSearch else thing
    cached_search = self.session.query(ShodanSearch).filter_by(string=thing).all()
    
    return None if len(cached_search) == 0 else cached_search[0]

  def remove(self, search_term):
    cached_search = self.search(search_term)
    if cached_search != None:
      self.session.delete(cached_search)
      self.session.commit()

  def add(self, shodan_search):
    self.remove(shodan_search)
    self.session.add(shodan_search)
    self.session.commit()


# ##############################################################################
colorama.init(autoreset=True)
print u'Shodiff v1.0 by John Stojanovski\n'

parser = argparse.ArgumentParser()
parser.add_argument(u'shodan_keyword')
parser.add_argument(u'--baseline', action=u'store_true', help=u'Reset the baseline.')
parser.add_argument(u'--diff', action=u'store_true', help=u'Diff result against baseline.')
args = parser.parse_args()

print "Searching..."
shodan_result = Shodan().search(args.shodan_keyword)
print(str(shodan_result)), u'\n'
# FIXME: the case where there are no results...

# Make sure nobody tries to diff and basline at the same time...
if args.baseline and args.diff:
  print u'I\'m not going to let you to baseline and diff at the same time.\n'
  exit(1)

if args.baseline or args.diff:
  shodan_cache = ShodanCache()

  if args.diff:
    cached_result = shodan_cache.search(args.shodan_keyword)
    if cached_result == None:
      print u'No cached result available for compare; '
      args.baseline = True
    else:
      if cached_result.hosts == shodan_result.hosts:
        print u'Differences from cached result:',
        print colorama.Fore.GREEN + u'None (Same same).'
      else:
        print u'Differences from chached result:',
        print colorama.Fore.RED + u'Same same but different!\n'
        
        print u'Cached result:'
        print str(cached_result), u'\n'


  if args.baseline:
    print u'Caching results for next time...',
    shodan_cache.add(shodan_result)
    print u'Done.'





