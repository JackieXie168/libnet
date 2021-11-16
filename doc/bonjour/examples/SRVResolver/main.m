/*
    File:       main.m

    Contains:   A simple test program for the SRVResolver class.

    Written by: DTS

    Copyright:  Copyright (c) 2010 Apple Inc. All Rights Reserved.

    Disclaimer: IMPORTANT: This Apple software is supplied to you by Apple Inc.
                ("Apple") in consideration of your agreement to the following
                terms, and your use, installation, modification or
                redistribution of this Apple software constitutes acceptance of
                these terms.  If you do not agree with these terms, please do
                not use, install, modify or redistribute this Apple software.

                In consideration of your agreement to abide by the following
                terms, and subject to these terms, Apple grants you a personal,
                non-exclusive license, under Apple's copyrights in this
                original Apple software (the "Apple Software"), to use,
                reproduce, modify and redistribute the Apple Software, with or
                without modifications, in source and/or binary forms; provided
                that if you redistribute the Apple Software in its entirety and
                without modifications, you must retain this notice and the
                following text and disclaimers in all such redistributions of
                the Apple Software. Neither the name, trademarks, service marks
                or logos of Apple Inc. may be used to endorse or promote
                products derived from the Apple Software without specific prior
                written permission from Apple.  Except as expressly stated in
                this notice, no other rights or licenses, express or implied,
                are granted by Apple herein, including but not limited to any
                patent rights that may be infringed by your derivative works or
                by other works in which the Apple Software may be incorporated.

                The Apple Software is provided by Apple on an "AS IS" basis. 
                APPLE MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING
                WITHOUT LIMITATION THE IMPLIED WARRANTIES OF NON-INFRINGEMENT,
                MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
                THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
                COMBINATION WITH YOUR PRODUCTS.

                IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT,
                INCIDENTAL OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
                TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
                DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING IN ANY WAY
                OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
                OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY
                OF CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY OR
                OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE POSSIBILITY OF
                SUCH DAMAGE.

*/

#include "SRVResolver.h"

@interface Main : NSObject <SRVResolverDelegate>
{
    SRVResolver *   _resolver;
}
- (BOOL)runWithSRVName:(NSString *)srvName;
@end

@interface Main ()

@property (nonatomic, retain, readwrite) SRVResolver *  resolver;
@end

@implementation Main

- (void)dealloc
{
    [self->_resolver stop];
    [self->_resolver release];
    [super dealloc];
}

@synthesize resolver = _resolver;

- (BOOL)runWithSRVName:(NSString *)srvName
    // The Objective-C 'main' for this program.  It creates a SimplePing object 
    // and runs the runloop sending pings and printing the results.
{
    assert(self.resolver == nil);
    
    self.resolver = [[[SRVResolver alloc] initWithSRVName:srvName] autorelease];
    assert(self.resolver != nil);

    if (NO) {
        self.resolver.delegate = self;
    }
    [self.resolver start];
    
    while ( ! self.resolver.isFinished ) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
    }

    if (self.resolver.error == nil) {
        NSLog(@"Priority   Weight Target:Port");
        NSLog(@"--------   ------ -----------");
        for (NSDictionary * result in self.resolver.results) {
            NSLog(
                @"%8d %8d %@:%d", 
                [[result objectForKey:kSRVResolverPriority] intValue],
                [[result objectForKey:kSRVResolverWeight  ] intValue],
                [result objectForKey:kSRVResolverTarget],
                [[result objectForKey:kSRVResolverPort    ] intValue]
            );
        }
    } else {
        NSLog(@"error = %@", self.resolver.error);
    }

    return (self.resolver.error == nil);
}

- (void)srvResolver:(SRVResolver *)resolver didReceiveResult:(NSDictionary *)result
{
    assert(resolver == self.resolver);
    assert(result != nil);
    NSLog(@"didReceiveResult %@", result);
}

- (void)srvResolver:(SRVResolver *)resolver didStopWithError:(NSError *)error
{
    assert(resolver == self.resolver);
    NSLog(@"didStopWithError %@", error);
}

@end

// _xmpp-server._tcp.gmail.com

int main(int argc, char* argv[])
{
    #pragma unused(argc)
    #pragma unused(argv)
    int                 retVal;
    BOOL                success;
    NSAutoreleasePool * pool;
    Main *              mainObj;
    
    pool = [[NSAutoreleasePool alloc] init];
    assert(pool != nil);
    
    retVal = EXIT_FAILURE;
    if (argc == 2) {
        mainObj = [[[Main alloc] init] autorelease];
        assert(mainObj != nil);
        
        success = [mainObj runWithSRVName:[NSString stringWithUTF8String:argv[1]]];
        if (success) {
            retVal = EXIT_SUCCESS;
        }
    } else {
        fprintf(stderr, "usage: %s name\n", getprogname());
    }
    
    [pool drain];
    
    return retVal;
}
