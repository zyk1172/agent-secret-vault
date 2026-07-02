#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

static NSString *ASVTelemetryStringValue(id object) {
    if (object == nil) {
        return @"";
    }
    if ([object respondsToSelector:@selector(stringValue)]) {
        NSString *value = ((NSString *(*)(id, SEL))objc_msgSend)(object, @selector(stringValue));
        if ([value isKindOfClass:[NSString class]]) {
            return value;
        }
    }
    NSString *description = [object description];
    return description ?: @"";
}

static NSUInteger ASVTelemetryLength(id self, SEL _cmd) {
    return [ASVTelemetryStringValue(self) length];
}

static unichar ASVTelemetryCharacterAtIndex(id self, SEL _cmd, NSUInteger index) {
    NSString *value = ASVTelemetryStringValue(self);
    if (index >= [value length]) {
        [NSException raise:NSRangeException format:@"Index %lu out of bounds for telemetry string length %lu", (unsigned long)index, (unsigned long)[value length]];
    }
    return [value characterAtIndex:index];
}

static void ASVTelemetryGetCharactersRange(id self, SEL _cmd, unichar *buffer, NSRange range) {
    [ASVTelemetryStringValue(self) getCharacters:buffer range:range];
}

static BOOL ASVTelemetryGetCString(id self, SEL _cmd, char *buffer, NSUInteger maxBufferCount, NSStringEncoding encoding) {
    return [ASVTelemetryStringValue(self) getCString:buffer maxLength:maxBufferCount encoding:encoding];
}

static const char *ASVTelemetryUTF8String(id self, SEL _cmd) {
    return [ASVTelemetryStringValue(self) UTF8String];
}

static BOOL ASVTelemetryCanBeConvertedToEncoding(id self, SEL _cmd, NSStringEncoding encoding) {
    return [ASVTelemetryStringValue(self) canBeConvertedToEncoding:encoding];
}

static void ASVAddStringSelectorIfMissing(Class cls, SEL selector, IMP implementation, const char *types) {
    if (cls != Nil && !class_getInstanceMethod(cls, selector)) {
        class_addMethod(cls, selector, implementation, types);
    }
}

__attribute__((constructor))
static void ASVInstallMetalTelemetryCompatibility(void) {
    if (@available(macOS 27.0, *)) {
        Class numberClass = NSClassFromString(@"__NSCFNumber") ?: [NSNumber class];
        ASVAddStringSelectorIfMissing(numberClass, @selector(length), (IMP)ASVTelemetryLength, "Q@:");
        ASVAddStringSelectorIfMissing(numberClass, @selector(characterAtIndex:), (IMP)ASVTelemetryCharacterAtIndex, "S@:Q");
        ASVAddStringSelectorIfMissing(numberClass, @selector(getCharacters:range:), (IMP)ASVTelemetryGetCharactersRange, "v@:^S{_NSRange=QQ}");
        ASVAddStringSelectorIfMissing(numberClass, @selector(getCString:maxLength:encoding:), (IMP)ASVTelemetryGetCString, "B@:*QQ");
        ASVAddStringSelectorIfMissing(numberClass, NSSelectorFromString(@"_getCString:maxLength:encoding:"), (IMP)ASVTelemetryGetCString, "B@:*QQ");
        ASVAddStringSelectorIfMissing(numberClass, @selector(UTF8String), (IMP)ASVTelemetryUTF8String, "*@:");
        ASVAddStringSelectorIfMissing(numberClass, @selector(canBeConvertedToEncoding:), (IMP)ASVTelemetryCanBeConvertedToEncoding, "B@:Q");
    }
}
