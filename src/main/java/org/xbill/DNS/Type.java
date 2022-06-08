// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.HashMap;
import java.util.function.Supplier;

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */
public final class Type {

  /** {@link ARecord Address} */
  public static final int A = 1;

  /** {@link NSRecord Name server} */
  public static final int NS = 2;

  /** {@link CNAMERecord Canonical name (alias)} */
  public static final int CNAME = 5;

  /** {@link SOARecord Start of authority} */
  public static final int SOA = 6;

  /** {@link PTRRecord Domain name pointer} */
  public static final int PTR = 12;


  /** {@link MXRecord Mail routing information} */
  public static final int MX = 15;

  /** {@link TXTRecord Text strings} */
  public static final int TXT = 16;

  /** {@link ISDNRecord ISDN calling address} */
  public static final int ISDN = 20;

  /** {@link SIGRecord Signature} */
  public static final int SIG = 24;

  /** {@link KEYRecord Key} */
  public static final int KEY = 25;

  /** {@link AAAARecord IPv6 address} */
  public static final int AAAA = 28;

  /**
   * Nimrod locator
   *
   * @see <a href="https://tools.ietf.org/html/draft-ietf-nimrod-dns-00">DNS Resource Records for
   *     Nimrod Routing Architecture</a>
   */
  public static final int NIMLOC = 32;

  /** {@link SRVRecord Server selection} */
  public static final int SRV = 33;

  /** {@link A6Record IPv6 address (historic)} */
  public static final int A6 = 38;

  /** {@link DNAMERecord Non-terminal name redirection} */
  public static final int DNAME = 39;

  /** {@link OPTRecord Options - contains EDNS metadata} */
  public static final int OPT = 41;

  /** {@link DSRecord Delegation Signer} */
  public static final int DS = 43;

  /** {@link IPSECKEYRecord IPSEC key} */
  public static final int IPSECKEY = 45;

  /** {@link RRSIGRecord Resource Record Signature} */
  public static final int RRSIG = 46;

  /** {@link NSECRecord Next Secure Name} */
  public static final int NSEC = 47;

  /** {@link DNSKEYRecord DNSSEC Key} */
  public static final int DNSKEY = 48;

  /** {@link NSEC3Record Next SECure, 3rd edition} */
  public static final int NSEC3 = 50;

  /** {@link TSIGRecord Transaction signature} */
  public static final int TSIG = 250;

  /** Incremental zone transfer */
  public static final int IXFR = 251;

  /** Zone transfer */
  public static final int AXFR = 252;

  /** Matches any type */
  public static final int ANY = 255;

  private static class TypeMnemonic extends Mnemonic {
    private final HashMap<Integer, Supplier<Record>> factories;

    public TypeMnemonic() {
      super("Type", CASE_UPPER);
      setPrefix("TYPE");
      setMaximum(0xFFFF);
      factories = new HashMap<>();
    }

    public void add(int val, String str, Supplier<Record> factory) {
      super.add(val, str);
      factories.put(val, factory);
    }

    public void replace(int val, String str, Supplier<Record> factory) {
      int oldVal = getValue(str);
      if (oldVal != -1) {
        if (oldVal != val) {
          throw new IllegalArgumentException(
              "mnemnonic \"" + str + "\" already used by type " + oldVal);
        } else {
          remove(val);
          factories.remove(val);
        }
      }

      add(val, str, factory);
    }

    @Override
    public void check(int val) {
      Type.check(val);
    }

    public Supplier<Record> getFactory(int val) {
      check(val);
      return factories.get(val);
    }
  }

  private static final TypeMnemonic types = new TypeMnemonic();

  static {
    types.add(A, "A", ARecord::new);
    types.add(NS, "NS", NSRecord::new);
    types.add(CNAME, "CNAME", CNAMERecord::new);
    types.add(SOA, "SOA", SOARecord::new);
    types.add(PTR, "PTR", PTRRecord::new);
    types.add(MX, "MX", MXRecord::new);
    types.add(TXT, "TXT", TXTRecord::new);
    types.add(SIG, "SIG", SIGRecord::new);
    types.add(KEY, "KEY", KEYRecord::new);
    types.add(AAAA, "AAAA", AAAARecord::new);
    types.add(SRV, "SRV", SRVRecord::new);
    types.add(A6, "A6", A6Record::new);
    types.add(DNAME, "DNAME", DNAMERecord::new);
    types.add(OPT, "OPT", OPTRecord::new);
    types.add(DS, "DS", DSRecord::new);
    types.add(RRSIG, "RRSIG", RRSIGRecord::new);
    types.add(NSEC, "NSEC", NSECRecord::new);
    types.add(DNSKEY, "DNSKEY", DNSKEYRecord::new);
    types.add(NSEC3, "NSEC3", NSEC3Record::new);
    types.add(TSIG, "TSIG", TSIGRecord::new);
    types.add(IXFR, "IXFR");
    types.add(AXFR, "AXFR");
    types.add(ANY, "ANY");
  }

  private Type() {}

  /**
   * Checks that a numeric Type is valid.
   *
   * @throws InvalidTypeException The type is out of range.
   */
  public static void check(int val) {
    if (val < 0 || val > 0xFFFF) {
      throw new InvalidTypeException(val);
    }
  }

  /**
   * Registers a new record type along with the respective factory. This allows the reimplementation
   * of existing types, the implementation of new types not (yet) supported by the library or the
   * implementation of "private use" record types. Note that the method is not synchronized and its
   * use may interfere with the creation of records in a multi-threaded environment. The method must
   * be used with care in order to avoid unexpected behaviour.
   *
   * @param val the numeric representation of the record type
   * @param str the textual representation of the record type
   * @param factory the factory; {@code null} may be used if there is no implementation available.
   *     In this case, records of the type will be represented by the {@link UNKRecord} class
   * @since 3.1
   */
  public static void register(int val, String str, Supplier<Record> factory) {
    types.replace(val, str, factory);
  }

  /**
   * Converts a numeric Type into a String
   *
   * @param val The type value.
   * @return The canonical string representation of the type
   * @throws InvalidTypeException The type is out of range.
   */
  public static String string(int val) {
    return types.getText(val);
  }

  /**
   * Converts a String representation of an Type into its numeric value.
   *
   * @param s The string representation of the type
   * @param numberok Whether a number will be accepted or not.
   * @return The type code, or -1 on error.
   */
  public static int value(String s, boolean numberok) {
    int val = types.getValue(s);
    if (val == -1 && numberok) {
      val = types.getValue("TYPE" + s);
    }
    return val;
  }

  /**
   * Converts a String representation of an Type into its numeric value
   *
   * @return The type code, or -1 on error.
   */
  public static int value(String s) {
    return value(s, false);
  }

  static Supplier<Record> getFactory(int val) {
    return types.getFactory(val);
  }

  /** Is this type valid for a record (a non-meta type)? */
  public static boolean isRR(int type) {
    switch (type) {
      case OPT:
      case TSIG:
      case IXFR:
      case AXFR:
      case ANY:
        return false;
      default:
        return true;
    }
  }
}
