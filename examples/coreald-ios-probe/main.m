#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Layout observed in ManagedBackgroundAssetsHelper's BADecryptLicenseChunk.
typedef struct {
    uint32_t kind;
    uint32_t reserved;
    uint32_t *length;
    uint8_t *bytes;
    uint64_t capacity;
} ALDChunkDescriptor;

_Static_assert(sizeof(ALDChunkDescriptor) == 0x20, "descriptor size");
_Static_assert(offsetof(ALDChunkDescriptor, length) == 0x08, "length offset");
_Static_assert(offsetof(ALDChunkDescriptor, bytes) == 0x10, "bytes offset");
_Static_assert(offsetof(ALDChunkDescriptor, capacity) == 0x18, "capacity offset");

typedef int32_t (*ALDStart)(const uint8_t *, size_t, const uint8_t *, size_t, void **);
typedef int32_t (*ALDDecrypt)(void *, ALDChunkDescriptor *);
typedef int32_t (*ALDStop)(void *);

static void *Resolve(void *handle, const char *name) {
    void *result = dlsym(handle, name);
    if (result != NULL) return result;
    char withUnderscore[128];
    snprintf(withUnderscore, sizeof(withUnderscore), "_%s", name);
    return dlsym(handle, withUnderscore);
}

@interface ProbeController : UIViewController
@property(nonatomic, strong) UITextView *output;
@property(nonatomic, strong) UIButton *runButton;
@end

@implementation ProbeController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [[UILabel alloc] init];
    title.text = @"CoreALD test host";
    title.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle2];

    UILabel *subtitle = [[UILabel alloc] init];
    subtitle.text = @"Controlled buffers only. No license bytes are stored or shown.";
    subtitle.numberOfLines = 0;
    subtitle.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    subtitle.textColor = UIColor.secondaryLabelColor;

    UIButton *run = [UIButton buttonWithType:UIButtonTypeSystem];
    [run setTitle:@"Run CoreALD checks" forState:UIControlStateNormal];
    run.titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    [run addTarget:self action:@selector(runChecks) forControlEvents:UIControlEventTouchUpInside];
    self.runButton = run;

    UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
    [copy setTitle:@"Copy result" forState:UIControlStateNormal];
    [copy addTarget:self action:@selector(copyResult) forControlEvents:UIControlEventTouchUpInside];

    UITextView *output = [[UITextView alloc] init];
    output.editable = NO;
    output.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    output.backgroundColor = UIColor.secondarySystemBackgroundColor;
    output.layer.cornerRadius = 10;
    output.text = @"Tap Run to load the private framework and test its entry points.\n";
    self.output = output;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[title, subtitle, run, copy, output]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:18],
        [stack.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-18],
        [stack.topAnchor constraintEqualToAnchor:safe.topAnchor constant:18],
        [stack.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-18],
    ]];
}

- (void)append:(NSString *)line {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.output.text = [self.output.text stringByAppendingFormat:@"%@\n", line];
        NSRange end = NSMakeRange(self.output.text.length, 0);
        [self.output scrollRangeToVisible:end];
    });
}

- (void)copyResult {
    UIPasteboard.generalPasteboard.string = self.output.text;
}

- (void)runChecks {
    self.runButton.enabled = NO;
    self.output.text = @"";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        const char *path = "/System/Library/PrivateFrameworks/CoreALD.framework/CoreALD";
        void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
            const char *error = dlerror();
            [self append:[NSString stringWithFormat:@"dlopen failed: %s", error ?: "unknown"]];
            dispatch_async(dispatch_get_main_queue(), ^{ self.runButton.enabled = YES; });
            return;
        }

        ALDStart start = (ALDStart)Resolve(handle, "CWeMQvFE");
        ALDDecrypt decrypt = (ALDDecrypt)Resolve(handle, "FbLnABIk");
        ALDStop stop = (ALDStop)Resolve(handle, "OZpDoyky");
        [self append:[NSString stringWithFormat:@"CoreALD loaded; start=%@ decrypt=%@ stop=%@",
                      start ? @"yes" : @"no", decrypt ? @"yes" : @"no",
                      stop ? @"yes" : @"no"]];
        if (start == NULL || decrypt == NULL || stop == NULL) {
            dlclose(handle);
            dispatch_async(dispatch_get_main_queue(), ^{ self.runButton.enabled = YES; });
            return;
        }

        uint8_t bufferA[256], bufferB[256];
        for (size_t i = 0; i < sizeof(bufferA); ++i) {
            bufferA[i] = (uint8_t)i;
            bufferB[i] = (uint8_t)(255 - i);
        }
        const size_t cases[][2] = {{0, 0}, {16, 16}, {32, 16}, {32, 32}};
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            size_t lenA = cases[i][0], lenB = cases[i][1];
            void *session = NULL;
            int32_t status = start(bufferA, lenA, bufferB, lenB, &session);
            [self append:[NSString stringWithFormat:@"start A=%zu B=%zu → %d (0x%08x), session=%@",
                          lenA, lenB, status, (uint32_t)status,
                          session ? @"yes" : @"no"]];

            if (status == 0 && session != NULL) {
                uint8_t chunk[32], original[32];
                for (size_t j = 0; j < sizeof(chunk); ++j) chunk[j] = (uint8_t)j;
                memcpy(original, chunk, sizeof(chunk));
                uint32_t length = sizeof(chunk);
                ALDChunkDescriptor descriptor = {1, 0, &length, chunk, sizeof(chunk)};
                int32_t chunkStatus = decrypt(session, &descriptor);
                [self append:[NSString stringWithFormat:@"test chunk → %d (0x%08x), length=%u, changed=%@",
                              chunkStatus, (uint32_t)chunkStatus, length,
                              memcmp(original, chunk, sizeof(chunk)) ? @"yes" : @"no"]];
            }
            if (session != NULL) {
                int32_t stopStatus = stop(session);
                [self append:[NSString stringWithFormat:@"stop → %d (0x%08x)",
                              stopStatus, (uint32_t)stopStatus]];
            }
        }
        dlclose(handle);
        [self append:@"Done."];
        dispatch_async(dispatch_get_main_queue(), ^{ self.runButton.enabled = YES; });
    });
}
@end

@interface ProbeSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation ProbeSceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)options {
    (void)session;
    (void)options;
    if (![scene isKindOfClass:UIWindowScene.class]) return;
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    self.window.rootViewController = [[ProbeController alloc] init];
    [self.window makeKeyAndVisible];
}
@end

@interface ProbeDelegate : UIResponder <UIApplicationDelegate>
@end

@implementation ProbeDelegate
- (UISceneConfiguration *)application:(UIApplication *)application
    configurationForConnectingSceneSession:(UISceneSession *)session
    options:(UISceneConnectionOptions *)options {
    (void)application;
    (void)options;
    UISceneConfiguration *configuration =
        [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:session.role];
    configuration.delegateClass = ProbeSceneDelegate.class;
    return configuration;
}
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    (void)application;
    (void)options;
    return YES;
}
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(ProbeDelegate.class));
    }
}
