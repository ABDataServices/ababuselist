/*************************************************************************
 *
 * Confidential Trade Secret
 * Copyright (c) 2022 AB Data Services, Oakland Park Florida, USA,
 * as an unpublished work.  All rights reserved.
 *
 *************************************************************************
 *
 * Module Name:
 *   $Source: $
 *
 * Creator:
 *   $Author: $
 *   $Date: $
 *
 * Purpose:
 *   $Description: $
 *
 * Revision history:
 *
 *   $Header: $
 *
 *   $Log: $
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * abuseipdb maximum limits
 */
#define BUFSIZE  2097152  /* 2MB */
#define MAXLINES 10000

/*
 * Data types
 */
typedef unsigned char uchar;

typedef struct abuse_t
{
  uint32_t        ipv4;
  uchar            ip[ 16 ];
  uchar*           categories;
  uchar*           date;
  uchar*           comment;
  struct abuse_t* prior;
  struct abuse_t* next;
} ABUSE_T, * pABUSE_T;

/*
 * Globals for list storage
 */
int      addrCount = 0;
pABUSE_T firstAddr = NULL;

/*
 * This function converts an IPv4 string address to the host format integral
 *   format. It will return 0 if the address did not convert.
 */
uint32_t convertIP( uchar *src )
{
  uint32_t nAddr  = 0;
  uchar*   buffer = strdup( src );
  uchar*   ptr    = buffer;
  uchar*   ptr2   = NULL;
  uchar    byte0  = 0;
  uchar    byte1  = 0;
  uchar    byte2  = 0;
  uchar    byte3  = 0;
  if ( ptr && ( ptr2 = strchr( ptr, '.' ) ) != NULL )
    {
      int val = -1;
      *ptr2 = 0;
      val = atoi( ptr );
      /*
       * 0 is not a valid first tuple
       */
      if ( val > 0 && val < 256 )
        {
          byte0 = val;
          ptr = ++ptr2;
          if ( ptr && *ptr && ( ptr2 = strchr( ptr, '.' ) ) != NULL )
            {
              *ptr2 = 0;
              val = atoi( ptr );
              /*
               * second through fourth tuples can be 0
               */
              if ( val >= 0 && val < 256 )
                {
                  byte1 = val;
                  ptr = ++ptr2;
                  if ( ptr && ( ptr2 = strchr( ptr, '.' ) ) != NULL )
                    {
                      *ptr2 = 0;
                      val = atoi( ptr );
                      if ( val >= 0 && val < 256 )
                        {
                          int size;
                          byte2 = val;
                          ptr = ++ptr2;
                          if ( ptr && *ptr && ( size = strlen( ptr ) ) > 0 &&
                               size < 4 )
                            {
                              ptr2 = ptr + size;
                              if ( *ptr2 != 0 )
                                *ptr2 = 0;
                              val = atoi( ptr );
                              if ( val >= 0 && val < 256 )
                                {
                                  byte3 = val;
                                  ptr = (char*) &nAddr;
                                  ptr[ 0 ] = byte0;
                                  ptr[ 1 ] = byte1;
                                  ptr[ 2 ] = byte2;
                                  ptr[ 3 ] = byte3;
                                }
                              else
                                fprintf( stderr, "G:Failed to convert %s: "
                                         "%c %c %c %c\n",
                                         buffer, byte0, byte1, byte2, byte3 );
                            }
                          else
                            fprintf( stderr,
                                     "F:Failed to convert %s: %c %c %c %c\n",
                                     buffer, byte0, byte1, byte2, byte3 );
                        }
                      else
                        fprintf( stderr,
                                 "E:Failed to convert %s: %c %c %c %c\n",
                                 buffer, byte0, byte1, byte2, byte3 );
                    }
                  else
                    fprintf( stderr, "D:Failed to convert %s: %c %c %c %c\n",
                             buffer, byte0, byte1, byte2, byte3 );
                }
              else
                fprintf( stderr, "C:Failed to convert %s: %c %c %c %c\n",
                         buffer, byte0, byte1, byte2, byte3 );
            }
          else
            fprintf( stderr, "B:Failed to convert %s: %c %c %c %c\n",
                     buffer, byte0, byte1, byte2, byte3 );
        }
      else
        fprintf( stderr, "Failed to convert %s: %c %c %c %c\n",
                 buffer, byte0, byte1, byte2, byte3 );
      free( buffer );
    }
  else
    fprintf( stderr, "A:Failed to convert %s: %c %c %c %c\n",
             buffer, byte0, byte1, byte2, byte3 );
  return ( ntohl( nAddr ) );
}

/*
 * insertBefore() returns a pointer to the next address after the one passed
 */
pABUSE_T insertBefore( uint32_t hAddr )
{
  pABUSE_T abuseAddr = firstAddr;
  pABUSE_T lastAddr  = NULL;
  while ( abuseAddr && hAddr > 0 && hAddr > abuseAddr->ipv4 )
    {
      lastAddr = abuseAddr;
      abuseAddr = abuseAddr->next;
    }
  return abuseAddr ? abuseAddr : lastAddr;
}

/*
 * matchAddress() returns a pointer to the existing matching hAddr or NULL
 *   if this address is new.
 */
pABUSE_T matchAddress( uint32_t hAddr )
{
  pABUSE_T thisAddr = firstAddr;
  /*
   * Advance through the list while hAddr is larger than the addr in struct
   */
  while ( thisAddr && hAddr > 0 && hAddr > thisAddr->ipv4 )
    thisAddr = thisAddr->next;
  /*
   * If we have a structure and the ip addresses match return it
   */
  if ( thisAddr && hAddr == thisAddr->ipv4 )
    return thisAddr;
  else
    return NULL;
}

/*
 * testListSort() walks through the list, ensuring that the items are in
 *   correct order
 */
int testListSort( void )
{
  int      retVal   = 0;
  int      i        = 0;
  pABUSE_T workAddr = firstAddr;
  uint32_t lastIP4  = 0;

  while ( workAddr && workAddr->next )
    {
      /*
       * If we repeat an address or the address decreases, add 1 to return
       */
      if ( lastIP4 >= workAddr->ipv4 )
        {
          fprintf( stderr, "address %d less than prior: %08x %08x\n", i,
                   workAddr->ipv4, lastIP4 );
          retVal += 1;
        }
      /*
       * increment counter, store this address and advance to next structure
       */
      i++;
      lastIP4 = workAddr->ipv4;
      workAddr = workAddr->next;
    }
  return retVal;
}

/*
 * processLine() parses the fields of the input line to their values and
 *   adds a new structure if the ip address is new.
 */
int processLine( uchar *src )
{
  int      retVal = 0;
  uchar*   buffer = strdup( src );
  uchar*   ptr    = NULL;
  uchar*   endPtr = NULL;
  uint32_t hAddr;
  uchar*   addr;
  uchar*   categories;
  uchar*   date;
  uchar*   comment;
  pABUSE_T priorAddr = NULL;
  pABUSE_T nextAddr  = NULL;
  pABUSE_T thisAddr  = NULL;

  /*
   * Ensure we allocated a local buffer
   */
  if ( buffer )
    {
      /*
       * Locate the separator for first two fields
       */
      ptr = buffer;
      if ( ptr && *ptr && ( endPtr = strchr( ptr, ',' ) ) != NULL )
        {
          /*
           * Convert IP address to integral value
           */
          *endPtr = 0;
          hAddr = convertIP( ptr );
          if ( hAddr > 0 )
            {
              /*
               * Copy the address string and advance to next field
               */
              addr = strdup( ptr );
              ptr = ++endPtr;
              if ( ptr && *ptr )
                {
                  /*
                   * Locate the separator for the second and third fields
                   */
                  if ( ( *ptr == '\"' && ( endPtr = strstr( ptr, "\","
                                                           ) )  != NULL )
                       || ( ( endPtr = strchr( ptr, ',' ) ) != NULL ) )
                    {
                      /*
                       * If the field starts with a single " make sure we skip
                       *   the " at the end, too
                       */
                      if ( *ptr == '"' )
                        endPtr++;
                      *endPtr = 0;
                      /*
                       * Copy categories string
                       */
                      categories = strdup( ptr );
                      if ( categories )
                        {
                          /*
                           * Advance to third  field
                           */
                          ptr = ++endPtr;
                          if ( ptr && *ptr && ( ( endPtr = strchr( ptr, ',' )
                                                  ) != NULL ) )
                            {
                              *endPtr = 0;
                              /*
                               * Copy the date string
                               */
                              date    = strdup( ptr );
                              if ( date )
                                {
                                  /*
                                   * Advance to final field
                                   */
                                  ptr = ++endPtr;
                                  endPtr = ptr + strlen( ptr );
                                  if ( ptr && *ptr && *endPtr == 0 )
                                    {
                                      int size = sizeof( ABUSE_T );

                                      /*
                                       * Copy the comment and allocate our
                                       *   structure
                                       */
                                      comment = strdup( ptr );
                                      thisAddr = malloc( size );
                                      /*
                                       * Ensure we don't have this address
                                       *   already.
                                       */
                                      if ( comment && thisAddr &&
                                           matchAddress( hAddr ) == NULL )
                                        {
                                          /*
                                           * Initialize our structure
                                           */
                                          memset( thisAddr, 0, size );
                                          thisAddr->ipv4 = hAddr;
                                          strcpy( thisAddr->ip, addr );
                                          thisAddr->categories = categories;
                                          thisAddr->date       = date;
                                          thisAddr->comment    = comment;
                                          /*
                                           * Find the insertion point
                                           */
                                          nextAddr = insertBefore( hAddr );
                                          /*
                                           * Insert somewhere after the first
                                           */
                                          if ( nextAddr )
                                            {
                                              thisAddr->next  = nextAddr;
                                              priorAddr       = nextAddr->prior;
                                              thisAddr->prior = priorAddr;
                                              if ( priorAddr )
                                                {
                                                  if ( priorAddr->next
                                                       != nextAddr )
                                                    fprintf( stderr, "List "
                                                             "mismatch!!! "
                                                             "prior->next: "
                                                             "%08llx next: "
                                                             "%08llx\n",
                                                             priorAddr->next,
                                                             nextAddr );
                                                  priorAddr->next = thisAddr;
                                                }
                                              nextAddr->prior = thisAddr;
                                              if ( firstAddr == nextAddr )
                                                firstAddr = thisAddr;
                                            }
                                          /*
                                           * This address should be before the
                                           *   first already stored.
                                           */
                                          else if ( firstAddr )
                                            {
                                              thisAddr->next   = firstAddr;
                                              firstAddr->prior = thisAddr;
                                              firstAddr        = thisAddr;
                                            }
                                          /*
                                           * Or this address is the very first
                                           *   in our list
                                           */
                                          else
                                            firstAddr = thisAddr;
                                          retVal = ++addrCount;
                                        }
                                      /*
                                       * If this would be duplicate, free the
                                       *   memory since we don't store dups.
                                       */
                                      else if ( thisAddr )
                                        free( thisAddr );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
      /*
       * Free our local copy of the input string
       */
      free( buffer );
    }
  return retVal;
}

/*
 * Main program code
 */
int main( int argc, uchar* argv[] )
{
  int    retVal     = 0;
  off_t  position   = -1;
  off_t  desiredPos = -1;
  uchar* filename   = NULL;
  uchar* ptr        = NULL;
  uchar* endPtr     = NULL;
  int    fd         = -1;
  size_t size       = -1;
  int    lines      = 0;
  uchar* buffer     = NULL;

  /*
   * Test and setup arguments
   */
  if ( argc == 2 )
    {
      filename = argv[ 1 ];
      /*
       * Open the input file exclusively
       */
      if ( ( fd = open( filename, O_RDWR | O_EXCL ) ) != -1 )
        {
          /*
           * Determine file size
           */
          desiredPos = lseek( fd, 0, SEEK_END );
          if ( desiredPos != (off_t) -1 )
            {
              /*
               * Allocate a block of memory for the file contents
               */
              if ( ( buffer = malloc( desiredPos ) ) != NULL )
                {
                  /*
                   * Rewind to beginning of file
                   */
                  if ( lseek( fd, 0, SEEK_SET ) != (off_t) -1 )
                    {
                      /*
                       * Now read entire file to count newlines
                       */
                      if ( ( size = read( fd, buffer, desiredPos )
                             ) == desiredPos && size > 0 )
                        {
                          uchar* lPtr = NULL;
                          /*
                           * We can close the file since we have it in memory.
                           */
                          close( fd );
                          /*
                           * Set our end and work pointers
                           */
                          ptr    = buffer;
                          endPtr = ptr + size - 1;
                          /*
                           * Cycle through all data, unless we have already
                           *   reached the maximum line count.
                           */
                          while ( lines < MAXLINES && ptr < endPtr )
                            {
                              /*
                               * Set up pointer to the current line
                               */
                              lPtr = ptr;
                              while ( ptr < endPtr && *ptr != '\n' )
                                ptr++;
                              /*
                               * Once we have a newline, process the file
                               */
                              if ( ptr <= endPtr && *ptr == '\n' )
                                {
                                  int lLines = 0;
                                  /*
                                   * processLine() returns 0 if the address
                                   *   is a duplicate, otherwise it returns
                                   *   the total number of addresses in  list.
                                   */
                                  *ptr = 0;
                                  lLines = processLine( lPtr );
                                  /*
                                   * This maintains the current allocated
                                   *   address count.
                                   */
                                  lines = lLines > 0 ? lLines : lines;
                                  ptr++;
                                }
                            }
                          /*
                           * If we have any data
                           */
                          if ( lines <= MAXLINES && addrCount > 0 )
                            {
                              int outLines = 0;
                              pABUSE_T workAddr = firstAddr;
                              /*
                               * Check for any sort error
                               */
                              if ( ! testListSort() )
                                {
                                  /*
                                   * Walk the list
                                   */
                                  while ( workAddr && outLines < MAXLINES )
                                    {
                                      uint32_t lastIp4 = 0;
                                      /*
                                       * Somehow a duplicate address is tacked
                                       *   on the very end of the list. This
                                       *   kludge prevents us from printing it
                                       *   in our output.
                                       */
                                      if ( lastIp4 < workAddr->ipv4 )
                                        {
                                          fprintf( stdout, "%s,%s,%s,%s\n",
                                                   workAddr->ip,
                                                   workAddr->categories,
                                                   workAddr->date,
                                                   workAddr->comment );
                                          outLines++;
                                          lastIp4 = workAddr->ipv4;
                                          /*
                                           * Advance pointer if next address
                                           *   is larger.
                                           */
                                          if ( workAddr->next &&
                                               lastIp4 < workAddr->next->ipv4 )
                                            workAddr = workAddr->next;
                                          /*
                                           * Otherwise, we're done since we
                                           *   checked the sort sequence above
                                           */
                                          else
                                            workAddr = NULL;
                                        }
                                      else
                                        workAddr = NULL;
                                    }
                                  /*
                                   * Walk the list, freeing all memory as we go
                                   */
                                  workAddr = firstAddr;
                                  while ( workAddr )
                                    {
                                      pABUSE_T newFirst = workAddr->next;
                                      int      abSize   = sizeof( ABUSE_T );
                                      free( workAddr->categories );
                                      free( workAddr->date );
                                      free( workAddr->comment );
                                      memset( workAddr, 0, abSize );
                                      free( workAddr );
                                      workAddr = newFirst;
                                    }
                                  firstAddr = NULL;
                                }
                            }
                          memset( buffer, 0, desiredPos );
                          free( buffer );
                        }
                      else
                        {
                          fprintf( stderr, "Error reading file: %s  offset: %ld"
                                   "  errno: %d\n", filename,
                                   desiredPos, errno );
                          retVal = 6;
                        }
                    }
                  else
                    {
                      fprintf( stderr, "Error rewinding file: %d\n", errno );
                      retVal = 5;
                    }
                }
              else
                {
                  fprintf( stderr, "Unable to allocate file buffer: %d\n",
                           errno );
                  retVal = 4;
                }
            }
          else
            {
              fprintf( stderr, "Error determining file size: %d\n", errno );
              retVal = 3;
            }
        }
      else
        {
          fprintf( stderr, "Unable to open file: %s %d\n", filename,
                   errno );
          retVal = 2;
        }
    }
  else
    {
      fprintf( stderr, "usage: %s <filename> <size_in_KB>\n", argv[ 0 ] );
      fprintf( stderr, "\twhere <size_in_KB> is the maximum file size to be "
               "truncated at the\n" );
      fprintf( stderr, "\t\tnearest newline character preceeding the size.\n" );
      retVal = 1;
    }
  return retVal;
}
