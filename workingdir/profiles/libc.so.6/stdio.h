/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*	THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF AT&T	*/
/*	The copyright notice above does not evidence any   	*/
/*	actual or intended publication of such source code.	*/

/*
 * User-visible pieces of the ANSI C standard I/O package.
 */

#ifndef _STDIO_H
#define	_STDIO_H

#pragma ident	"@(#)stdio.h	1.37	95/08/29 SMI"	/* SVr4.0 2.34.1.2 */

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _SIZE_T
#define	_SIZE_T
typedef unsigned int	size_t;
#endif

typedef long	fpos_t;

#ifndef NULL
#define	NULL	0
#endif

#define	BUFSIZ	1024

#ifdef	__STDC__
/*
 * Note that the following construct, "!#machine(name)", is a non-standard
 * extension to ANSI-C.  It is maintained here to provide compatibility
 * for existing compilations systems, but should be viewed as transitional
 * and may be removed in a future release.  If it is required that this
 * file not contain this extension, edit this file to remove the offending
 * condition.
 *
 * The value of _NFILE is defined in the Processor Specific ABI.  The value
 * is chosen for historical reasons rather than for truly processor related
 * attribute.  Note that the SPARC Processor Specific ABI uses the common
 * UNIX historical value of 20 so it is allowed to fall through.
 */
#if #machine(i386) || defined(__i386)
#define	_NFILE	60	/* initial number of streams: Intel x86 ABI */
#else
#define	_NFILE	20	/* initial number of streams: SPARC ABI and default */
#endif
#else	/* __STDC__ */
#if defined(i386) || defined(__i386)
#define	_NFILE	60	/* initial number of streams: Intel x86 ABI */
#else
#define	_NFILE	20	/* initial number of streams: SPARC ABI and default */
#endif
#endif	/* __STDC__ */

#define	_SBFSIZ	8	/* compatibility with shared libs */

#define	_IOFBF		0000	/* full buffered */
#define	_IOLBF		0100	/* line buffered */
#define	_IONBF		0004	/* not buffered */
#define	_IOEOF		0020	/* EOF reached on read */
#define	_IOERR		0040	/* I/O error from system */

#define	_IOREAD		0001	/* currently reading */
#define	_IOWRT		0002	/* currently writing */
#define	_IORW		0200	/* opened for reading and writing */
#define	_IOMYBUF	0010	/* stdio malloc()'d buffer */

#ifndef EOF
#define	EOF	(-1)
#endif

#define	FOPEN_MAX	_NFILE
#define	FILENAME_MAX    1024	/* max # of characters in a path name */

#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2
#define	TMP_MAX		17576	/* 26 * 26 * 26 */

#if defined(__EXTENSIONS__) || __STDC__ - 0 == 0 || \
		defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE)

#define	L_ctermid	9
#define	L_cuserid	9
#endif

#if defined(__EXTENSIONS__) || ((__STDC__ - 0 == 0 && \
		!defined(_POSIX_C_SOURCE))) || defined(_XOPEN_SOURCE)

#define	P_tmpdir	"/var/tmp/"
#endif /* defined(__EXTENSIONS__) || ((__STDC__ - 0 == 0 && ... */

#if defined(_XOPEN_SOURCE) && (_XOPEN_VERSION - 0 == 4)
#ifndef _VA_LIST
#define	_VA_LIST
typedef void *va_list;
#endif
#endif /* defined(_XOPEN_SOURCE) && (_XOPEN_VERSION - 0 == 4) */

#define	L_tmpnam	25	/* (sizeof(P_tmpdir) + 15) */

#if defined(__STDC__)
#define	stdin	(&__iob[0])
#define	stdout	(&__iob[1])
#define	stderr	(&__iob[2])
#else
#define	stdin	(&_iob[0])
#define	stdout	(&_iob[1])
#define	stderr	(&_iob[2])
#endif	/* __STDC__ */

typedef struct	/* needs to be binary-compatible with old versions */
{
#ifdef _STDIO_REVERSE
	unsigned char	*_ptr;	/* next character from/to here in buffer */
	int		_cnt;	/* number of available characters in buffer */
#else
	int		_cnt;	/* number of available characters in buffer */
	unsigned char	*_ptr;	/* next character from/to here in buffer */
#endif
	unsigned char	*_base;	/* the buffer */
	unsigned char	_flag;	/* the state of the stream */
	unsigned char	_file;	/* UNIX System file descriptor */
} FILE;

#if defined(__STDC__)
extern FILE		__iob[_NFILE];
#else
extern FILE		_iob[_NFILE];
#endif	/* __STDC__ */
extern FILE		*_lastbuf;
extern unsigned char	*_bufendtab[];
#ifndef _STDIO_ALLOCATE
extern unsigned char	 _sibuf[], _sobuf[];
#endif

#if defined(__STDC__)

extern int	remove(const char *);
extern int	rename(const char *, const char *);
extern FILE	*tmpfile(void);
extern char	*tmpnam(char *);
#if	defined(__EXTENSIONS__) || defined(_REENTRANT)
extern char	*tmpnam_r(char *);
#endif /* defined(__EXTENSIONS__) || defined(_REENTRANT) */
extern int	fclose(FILE *);
extern int	fflush(FILE *);
extern FILE	*fopen(const char *, const char *);
extern FILE	*freopen(const char *, const char *, FILE *);
extern void	setbuf(FILE *, char *);
extern int	setvbuf(FILE *, char *, int, size_t);
/* PRINTFLIKE2 */
extern int	fprintf(FILE *, const char *, ...);
/* SCANFLIKE2 */
extern int	fscanf(FILE *, const char *, ...);
/* PRINTFLIKE1 */
extern int	printf(const char *, ...);
/* SCANFLIKE1 */
extern int	scanf(const char *, ...);
/* PRINTFLIKE2 */
extern int	sprintf(char *, const char *, ...);
/* SCANFLIKE2 */
extern int	sscanf(const char *, const char *, ...);
#if defined(_XOPEN_SOURCE) && (_XOPEN_VERSION - 0 == 4)
extern int	vfprintf(FILE *, const char *, va_list);
extern int	vprintf(const char *, va_list);
extern int	vsprintf(char *, const char *, va_list);
#else
extern int	vfprintf(FILE *, const char *, void *);
extern int	vprintf(const char *, void *);
extern int	vsprintf(char *, const char *, void *);
#endif /* defined (_XOPEN_SOURCE) && (_XOPEN_VERSION - 0 == 4) */
extern int	fgetc(FILE *);
extern char	*fgets(char *, int, FILE *);
extern int	fputc(int, FILE *);
extern int	fputs(const char *, FILE *);
extern int	getc(FILE *);
extern int	getchar(void);
extern char	*gets(char *);
extern int	putc(int, FILE *);
extern int	putchar(int);
extern int	puts(const char *);
extern int	ungetc(int, FILE *);
extern size_t	fread(void *, size_t, size_t, FILE *);
extern size_t	fwrite(const void *, size_t, size_t, FILE *);
extern int	fgetpos(FILE *, fpos_t *);
extern int	fseek(FILE *, long, int);
extern int	fsetpos(FILE *, const fpos_t *);
extern long	ftell(FILE *);
extern void	rewind(FILE *);
extern void	clearerr(FILE *);
extern int	feof(FILE *);
extern int	ferror(FILE *);
extern void	perror(const char *);

extern int	__filbuf(FILE *);
extern int	__flsbuf(int, FILE *);

/*
 * The following are known to POSIX and XOPEN, but not to ANSI-C.
 */
#if defined(__EXTENSIONS__) || __STDC__ == 0 || \
		defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE)

extern FILE	*fdopen(int, const char *);
extern char	*ctermid(char *);
extern int	fileno(FILE *);

#endif	/* defined(__EXTENSIONS__) ||  __STDC__ == 0 ... */

/*
 * The following are known to POSIX.1c, but not to ANSI-C or XOPEN.
 */
#if	defined(__EXTENSIONS__) || defined(_REENTRANT) || \
	    (_POSIX_C_SOURCE - 0 >= 199506L)
extern void	flockfile(FILE *);
extern int	ftrylockfile(FILE *);
extern void	funlockfile(FILE *);
extern int	getc_unlocked(FILE *);
extern int	getchar_unlocked(void);
extern int	putc_unlocked(int, FILE *);
extern int	putchar_unlocked(int);

#endif	/* defined(__EXTENSIONS__) || defined(_REENTRANT).. */

/*
 * The following are known to XOPEN, but not to ANSI-C or POSIX.
 */
#if defined(__EXTENSIONS__) || __STDC__ == 0 || defined(_XOPEN_SOURCE)

extern FILE	*popen(const char *, const char *);
extern char	*cuserid(char *);
extern char	*tempnam(const char *, const char *);
extern int	getopt(int, char *const *, const char *);
#if !defined(_XOPEN_SOURCE)
extern int	getsubopt(char **, char *const *, char **);
#endif /* !defined(_XOPEN_SOURCE) */
extern char	*optarg;
extern int	optind, opterr, optopt;
extern int	getw(FILE *);
extern int	putw(int, FILE *);
extern int	pclose(FILE *);

#endif	/* defined(__EXTENSIONS__) ||  __STDC__ == 0 ... */

#else	/* !defined __STDC__ */

#define	_bufend(p)	((fileno(p) < _NFILE) ? _bufendtab[(p)->_file] : \
			(unsigned char *)_realbufend(p))
#define	_bufsiz(p)	(_bufend(p) - (p)->_base)

extern int	remove();
extern int	rename();
extern FILE	*tmpfile();
extern char	*tmpnam();
#if	defined(__EXTENSIONS__) || defined(_REENTRANT)
extern char	*tmpnam_r();
#endif /* defined(__EXTENSIONS__) || defined(_REENTRANT) */
extern int	fclose();
extern int	fflush();
extern FILE	*fopen();
extern FILE	*freopen();
extern void	setbuf();
extern int	setvbuf();
extern int	fprintf();
extern int	fscanf();
extern int	printf();
extern int	scanf();
extern int	sprintf();
extern int	sscanf();
extern int	vfprintf();
extern int	vprintf();
extern int	vsprintf();
extern int	fgetc();
extern char	*fgets();
extern int	fputc();
extern int	fputs();
extern int	getc();
extern int	getchar();
extern char	*gets();
extern int	putc();
extern int	putchar();
extern int	puts();
extern int	ungetc();
extern size_t	fread();
extern size_t	fwrite();
extern int	fgetpos();
extern int	fseek();
extern int	fsetpos();
extern long	ftell();
extern void	rewind();
extern void	clearerr();
extern int	feof();
extern int	ferror();
extern void	perror();

extern int	_filbuf();
extern int	_flsbuf();

extern FILE	*fdopen();
extern char	*ctermid();
extern int	fileno();

#if	defined(__EXTENSIONS__) || defined(_REENTRANT) || \
	    (_POSIX_C_SOURCE - 0 >= 199506L)
extern void	flockfile();
extern int	ftrylockfile();
extern void	funlockfile();
extern int	getc_unlocked();
extern int	getchar_unlocked();
extern int	putc_unlocked();
extern int	putchar_unlocked();
#endif	/* defined(__EXTENSIONS__) || defined(_REENTRANT).. */

extern FILE	*popen();
extern char	*cuserid();
extern char	*tempnam();
extern int	getopt();
#if !defined(_XOPEN_SOURCE)
extern int	getsubopt();
#endif /* !defined(_XOPEN_SOURCE) */
extern char	*optarg;
extern int	optind, opterr, optopt;
extern int	getw();
extern int	putw();
extern int	pclose();

#endif	/* __STDC__ */

/*
 * Note that the following construct, "!#lint(on)", is a non-standard
 * extension to ANSI-C.  It is maintained here to provide compatibility
 * for existing compilations systems, but should be viewed as transitional
 * and may be removed in a future release.  If it is required that this
 * file not contain this extension, edit this file to remove the offending
 * condition.
 */
#if !defined(lint) && !defined(__lint)

#ifndef	_REENTRANT
#ifdef	__STDC__
#define	getc(p)		(--(p)->_cnt < 0 ? __filbuf(p) : (int)*(p)->_ptr++)
#define	putc(x, p)	(--(p)->_cnt < 0 ? __flsbuf((unsigned char) (x), (p)) \
				: (int)(*(p)->_ptr++ = (x)))
#else
#define	getc(p)		(--(p)->_cnt < 0 ? _filbuf(p) : (int) *(p)->_ptr++)
#define	putc(x, p)	(--(p)->_cnt < 0 ? \
			_flsbuf((unsigned char) (x), (p)) : \
			(int) (*(p)->_ptr++ = (unsigned char) (x)))
#endif	/* __STDC__ */
#define	getchar()	getc(stdin)
#define	putchar(x)	putc((x), stdout)
#define	clearerr(p)	((void)((p)->_flag &= ~(_IOERR | _IOEOF)))
#define	feof(p)		((p)->_flag & _IOEOF)
#define	ferror(p)	((p)->_flag & _IOERR)
#endif	/* _REENTRANT */

#if defined(__EXTENSIONS__) || (__STDC__ -0 == 0) || \
		defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE)
#define	fileno(p)	((p)->_file)
#endif	/* defined(__EXTENSIONS__) ||  __STDC__ == 0 ... */

#if	defined(__EXTENSIONS__) || defined(_REENTRANT) || \
	    (_POSIX_C_SOURCE - 0 >= 199506L)
#ifdef	__STDC__
#define	getc_unlocked(p)	(--(p)->_cnt < 0 \
					? __filbuf(p) \
					: (int)*(p)->_ptr++)
#define	putc_unlocked(x, p)	(--(p)->_cnt < 0 \
					? __flsbuf((unsigned char) (x), (p)) \
					: (int)(*(p)->_ptr++ = (x)))
#else
#define	getc_unlocked(p)	(--(p)->_cnt < 0 \
					? _filbuf(p) \
					: (int)*(p)->_ptr++)
#define	putc_unlocked(x, p)	(--(p)->_cnt < 0 \
					? _flsbuf((unsigned char) (x), (p)) \
					: (int)(*(p)->_ptr++ = (x)))
#endif	/* __STDC__ */
#define	getchar_unlocked()	getc_unlocked(stdin)
#define	putchar_unlocked(x)	putc_unlocked((x), stdout)
#endif	/* defined(__EXTENSIONS__) || defined(_REENTRANT).. */

#endif	/* !defined(lint) && !defined(__lint) */

#ifdef	__cplusplus
}
#endif

#endif	/* _STDIO_H */