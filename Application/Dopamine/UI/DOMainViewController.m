//
//  DOMainViewController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOMainViewController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOJailbreaker.h"
#import "DOGlobalAppearance.h"
#import "DOActionMenuButton.h"
#import "DOUpdateViewController.h"
#import "DOLogCrashViewController.h"
#import <pthread.h>
#import <sys/sysctl.h>
#import <libjailbreak/libjailbreak.h>

@interface DOMainViewController ()

@property DOJailbreakButton *jailbreakBtn;
@property NSArray<NSLayoutConstraint *> *jailbreakButtonConstraints;
@property DOActionMenuButton *updateButton;
@property(nonatomic) BOOL hideStatusBar;
@property(nonatomic) BOOL hideHomeIndicator;
@property(nonatomic) BOOL didPresentRootHideTrace;

@end

static NSString *const RootHideLastPresentedTraceKey = @"RootHideLastPresentedTrace";

@implementation DOMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupStack];
}

-(void)setupStack
{
    UIStackView *stackView = [[UIStackView alloc] init];
    [stackView setAxis:UILayoutConstraintAxisVertical];
    [stackView setAlignment:UIStackViewAlignmentTrailing];
    [stackView setDistribution:UIStackViewDistributionEqualSpacing];
    [stackView setTranslatesAutoresizingMaskIntoConstraints:NO];

    [self.view addSubview:stackView];


    int statusBarHeight = fmax(15, [[UIApplication sharedApplication] keyWindow].safeAreaInsets.top - 20);

    [NSLayoutConstraint activateConstraints:@[
        [stackView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:statusBarHeight],//-35
        [stackView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor multiplier:[DOGlobalAppearance isHomeButtonDevice] ? 0.78 : 0.73]
    ]];

    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
    {
        NSLayoutConstraint *relativeWidthConstraint = [stackView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.8];
        relativeWidthConstraint.priority = UILayoutPriorityDefaultHigh;
        NSLayoutConstraint *maxWidthConstraint = [stackView.widthAnchor constraintLessThanOrEqualToConstant:UI_IPAD_MAX_WIDTH];
        maxWidthConstraint.priority = UILayoutPriorityRequired;

        [NSLayoutConstraint activateConstraints:@[
            relativeWidthConstraint,
            maxWidthConstraint,
            [stackView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor]
        ]];
    }
    else
    {
        [NSLayoutConstraint activateConstraints:@[
            [stackView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:UI_PADDING],
            [stackView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-UI_PADDING],
        ]];
    }

    //Header
    DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage: [UIImage imageNamed:@"Dopamine"] subtitles: @[
        [DOGlobalAppearance mainSubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],
        [DOGlobalAppearance secondarySubtitleString:[NSString stringWithFormat:@"%@, ChatGPT", DOLocalizedString(@"Credits_Made_By")]],
    ]];
    
    [stackView addArrangedSubview:headerView];

    [NSLayoutConstraint activateConstraints:@[
        [headerView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:5],
        [headerView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor]
    ]];
    
    //Action Menu
    DOActionMenuView *actionView = [[DOActionMenuView alloc] initWithActions:@[
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Settings_Title") image:[UIImage systemImageNamed:@"gearshape" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"settings" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOSettingsController alloc] init] animated:YES];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Restart_SpringBoard_Title") image:[UIImage systemImageNamed:@"arrow.clockwise" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"respring" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] respring];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Reboot_Userspace_Title") image:[UIImage systemImageNamed:@"arrow.clockwise.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"reboot-userspace" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Credits_Title") image:[UIImage systemImageNamed:@"info.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"credits" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOCreditsViewController alloc] init] animated:YES];
        }]
    ] delegate:self];
    
    [stackView addArrangedSubview: actionView];

    [NSLayoutConstraint activateConstraints:@[
        [actionView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [actionView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
    ]];
    
    
    UIView *buttonPlaceHolder = [[UIView alloc] init];
    [buttonPlaceHolder setTranslatesAutoresizingMaskIntoConstraints:NO];
    [stackView addArrangedSubview:buttonPlaceHolder];
    [NSLayoutConstraint activateConstraints:@[
        [buttonPlaceHolder.heightAnchor constraintEqualToConstant:60]
    ]];
    
    //Jailbreak Button
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken] || [[DOEnvironmentManager sharedManager] isJailbrokenWithOtherJailbreak];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];

    NSString *jailbreakButtonTitle = [self jailbreakButtonTitle];
        
    UIImage *jailbreakButtonImage;
    if (isSupported)
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.open" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    else
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.slash" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    
    self.jailbreakBtn = [[DOJailbreakButton alloc] initWithAction: [UIAction actionWithTitle:jailbreakButtonTitle image:jailbreakButtonImage identifier:@"jailbreak" handler:^(__kindof UIAction * _Nonnull action) {
        [actionView hide];
        [self.jailbreakBtn expandButton: self.jailbreakButtonConstraints];

        self.updateButton.userInteractionEnabled = NO;
        [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
            [headerView setTransform:CGAffineTransformMakeTranslation(0, -25)];
            self.updateButton.alpha = 0;
        } completion:nil];
        
        [self startJailbreak];
        
    }]];
    self.jailbreakBtn.enabled = !isJailbroken && isSupported;

    [self.view addSubview:self.jailbreakBtn];

    [NSLayoutConstraint activateConstraints:(self.jailbreakButtonConstraints = @[
        [self.jailbreakBtn.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [self.jailbreakBtn.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
        [self.jailbreakBtn.heightAnchor constraintEqualToAnchor:buttonPlaceHolder.heightAnchor],
        [self.jailbreakBtn.centerYAnchor constraintEqualToAnchor:buttonPlaceHolder.centerYAnchor]
    ])];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.1 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        if ([[DOUIManager sharedInstance] environmentUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:YES];
            });
        }
        else if ([[DOUIManager sharedInstance] isUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:NO];
            });
        }
    });
}

- (NSString *)jailbreakButtonTitle
{
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];
    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];

    NSString *jailbreakButtonTitle = DOLocalizedString(@"Button_Jailbreak_Title");
    if (!isSupported)
        jailbreakButtonTitle = DOLocalizedString(@"Unsupported");
    else if (isJailbroken)
        jailbreakButtonTitle = DOLocalizedString(@"Status_Title_Jailbroken");
    else if (removeJailbreakEnabled)
        jailbreakButtonTitle = DOLocalizedString(@"Button_Remove_Jailbreak");
    
    return jailbreakButtonTitle;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self.jailbreakBtn.button setTitle:[self jailbreakButtonTitle] forState:UIControlStateNormal];
}

- (NSString *)rootHideTraceDiagnosisForTrace:(NSString *)trace
{
    // Prefer explicit failures over phase heuristics.  Keeping the last few
    // lines preserves both the low-level cause and the app-level wrapper (for
    // example a killed Bootstrap child followed by its raw wait status).
    NSMutableArray<NSString *> *failureLines = [NSMutableArray array];
    [trace enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
        if ([line containsString:@"FAILURE:"]) [failureLines addObject:line];
    }];
    if (failureLines.count > 0) {
        NSUInteger first = failureLines.count > 3 ? failureLines.count - 3 : 0;
        NSArray<NSString *> *lastFailures = [failureLines subarrayWithRange:NSMakeRange(first, failureLines.count - first)];
        return [NSString stringWithFormat:@"诊断结论：已记录明确错误，最后几条如下：\n%@", [lastFailures componentsJoinedByString:@"\n"]];
    }

    NSRange postRebootRange = [trace rangeOfString:@"[launchd] constructor entered; DOPAMINE_INITIALIZED=1" options:NSBackwardsSearch];
    if (postRebootRange.location != NSNotFound) {
        NSString *postRebootTrace = [trace substringFromIndex:postRebootRange.location];
        if ([postRebootTrace containsString:@"phase: starting post-reboot crash reporter"] &&
            ![postRebootTrace containsString:@"phase complete: post-reboot crash reporter"]) {
            return @"诊断结论：用户空间重启后的 launchd 已进入，但停在 crash reporter 初始化。";
        }
        if ([postRebootTrace containsString:@"phase: recovering boomerang primitives"] &&
            ![postRebootTrace containsString:@"phase complete: boomerang primitive recovery"]) {
            return @"诊断结论：用户空间重启后的 launchd 停在 boomerang 内核原语恢复阶段。";
        }
        if ([postRebootTrace containsString:@"phase: RootHide post-initialization"] &&
            ![postRebootTrace containsString:@"phase complete: RootHide post-initialization"]) {
            return @"诊断结论：用户空间重启后的 RootHide 服务初始化没有完成。";
        }
        if (![postRebootTrace containsString:@"[jailbreakd] phase complete: check-in succeeded"]) {
            return @"诊断结论：用户空间重启后的 launchd 已完成主要 Hook，但 jailbreakd 尚未完成 check-in。";
        }
    }
    else if ([trace containsString:@"[app] phase: invoking userspace reboot"]) {
        if (![trace containsString:@"[jbctl] reboot_userspace entered"]) {
            return @"诊断结论：App 已进入重启阶段，但 jbctl 没有开始执行，问题在 jbctl 的提权、spawn 或日志环境传递。";
        }
        if (![trace containsString:@"[jbctl] launchd userspace-reboot preflight returned 0"]) {
            return @"诊断结论：jbctl 已启动，但 launchd 的 userspace-reboot preflight 没有成功返回；请看最后一条 jbctl/launchd 日志。";
        }

        BOOL rebootXPCObserved = [trace containsString:@"[launchd] observed RB2_USERREBOOT XPC"];
        BOOL maintenanceFallbackStarted = [trace containsString:@"mmaintenanced is not running as a verified launchd child; starting native fallback"];
        BOOL maintenanceFallbackFailed = [trace containsString:@"FAILURE: no verified /usr/libexec/mmaintenanced reboot host is available"];
        BOOL watchdogInjectionStarted = [trace containsString:@"[jbctl] injecting userspace-reboot bridge into mmaintenanced"] ||
                                        [trace containsString:@"[jbctl] injecting watchdog reboot bridge into watchdogd"];
        BOOL watchdogInjectionReturned = [trace containsString:@"[jbctl] mmaintenanced reboot bridge injection returned"] ||
                                         [trace containsString:@"[jbctl] watchdog reboot bridge injection returned"];
        BOOL watchdogChannelReady = [trace containsString:@"[jbctl] reboot-host notification channel ready"] ||
                                    [trace containsString:@"[jbctl] watchdogd notification channel ready"];
        BOOL watchdogRequestPosted = [trace containsString:@"[jbctl] reboot-host userspace-reboot notification post returned 0"] ||
                                     [trace containsString:@"[jbctl] watchdogd userspace-reboot notification post returned 0"];
        BOOL watchdogRequestAcknowledged = [trace containsString:@"[jbctl] reboot-host acknowledged userspace-reboot request"] ||
                                           [trace containsString:@"[jbctl] watchdogd acknowledged userspace-reboot request"];
        BOOL watchdogRequestReceived = [trace containsString:@"[reboot-host] userspace-reboot request received"] ||
                                       [trace containsString:@"[watchdogd] userspace-reboot request received"];
        BOOL watchdogRebootCalled = [trace containsString:@"[reboot-host] calling reboot3 with RB2_USERREBOOT"] ||
                                    [trace containsString:@"[watchdogd] calling reboot3 with RB2_USERREBOOT"] ||
                                    [trace containsString:@"[jbctl] reboot-host reboot3 result returned"] ||
                                    [trace containsString:@"[jbctl] watchdogd reboot3 result returned"];
        __block BOOL watchdogRebootXPCObserved = NO;
        [trace enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
            BOOL verifiedMaintenanceHost = [line containsString:@" path=/usr/libexec/mmaintenanced "] &&
                                           [line containsString:@" reboot_entitlement=1 "];
            BOOL verifiedLegacyWatchdogHost = [line containsString:@" path=/usr/libexec/watchdogd "] &&
                                              [line containsString:@" watchdog_entitlement=1 "];
            if ([line containsString:@"[launchd] observed RB2_USERREBOOT XPC"] &&
                [line containsString:@" csops=0"] &&
                [line containsString:@" platform=1 "] &&
                (verifiedMaintenanceHost || verifiedLegacyWatchdogHost)) {
                watchdogRebootXPCObserved = YES;
                *stop = YES;
            }
        }];
        BOOL replacementMatched = [trace containsString:@"[launchd] userspace-reboot self-spawn matched"] ||
                                  [trace containsString:@"[launchd] userspace-reboot self-exec matched"];
        if ([trace containsString:@"[jbctl] reboot3 returned 0"] && !rebootXPCObserved) {
            return @"诊断结论：reboot3 返回成功，但 launchd 的 Hook 没观察到 RB2_USERREBOOT XPC；问题在系统重启消息路径或消息格式。";
        }
        if (maintenanceFallbackStarted && maintenanceFallbackFailed && !watchdogInjectionStarted) {
            return @"诊断结论：系统未运行 mmaintenanced，直接启动原生重启宿主也未通过验证；请查看 native mmaintenanced direct spawn、candidate 和 FAILURE 行。";
        }
        if (watchdogInjectionStarted && !watchdogInjectionReturned) {
            return @"诊断结论：已开始向 Apple 重启宿主注入桥，但 opainject 尚未返回；中断位于 task port、远程 dlopen 或构造函数执行阶段。";
        }
        if (watchdogInjectionReturned && !watchdogChannelReady) {
            return @"诊断结论：opainject 已返回，但重启宿主的通知监听器尚未通过握手；请查看 injection、readiness probe 和 FAILURE 行。";
        }
        if (watchdogChannelReady && !watchdogRequestPosted) {
            return @"诊断结论：重启宿主通知通道已就绪，但 jbctl 尚未成功投递 userspace-reboot 请求。";
        }
        if (watchdogRequestPosted &&
            !watchdogRequestAcknowledged && !watchdogRequestReceived && !rebootXPCObserved) {
            return @"诊断结论：jbctl 已投递重启通知，但重启宿主尚未确认收到；中断位于 Darwin notification 派发。";
        }
        if ((watchdogRequestAcknowledged || watchdogRequestReceived) &&
            !watchdogRebootCalled && !rebootXPCObserved) {
            return @"诊断结论：重启宿主已收到请求，但尚未进入 reboot3 调用。";
        }
        if ((watchdogRequestAcknowledged || watchdogRebootCalled) && !rebootXPCObserved) {
            return @"诊断结论：重启宿主已接收请求并进入重启路径，但 launchd 尚未观察到 RB2_USERREBOOT XPC。";
        }
        if (rebootXPCObserved && !watchdogRebootXPCObserved) {
            return @"诊断结论：launchd 收到了 RB2_USERREBOOT，但调用者不是已验证的平台重启宿主，或缺少对应权限；请查看 observed RB2_USERREBOOT 行。";
        }
        if (rebootXPCObserved && !replacementMatched) {
            __block BOOL callerAuthorizationVerified = NO;
            [trace enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
                if ([line containsString:@"userspace-reboot caller authorization after repair;"]) {
                    callerAuthorizationVerified = [line containsString:@"csops=0"] && [line containsString:@"platform=1"];
                    *stop = YES;
                }
            }];
            if (!callerAuthorizationVerified) {
                return @"诊断结论：RB2_USERREBOOT 已到达 launchd，但 jbctl 的运行时平台授权没有验证成功；请查看 caller authorization 行。";
            }
            if (![trace containsString:@"iOS 18 RB2 path: skipped legacy RootHide pre-teardown /Developer unmount"]) {
                return @"诊断结论：RB2_USERREBOOT 已到达 launchd，但仍执行了旧版 RootHide 的重启前副作用；当前构建没有包含 iOS 18 顺序修复。";
            }
            BOOL jailbreakdDispositionRecorded = [trace containsString:@"phase complete: temporary jailbreakd stopped before userspace reboot"] ||
                                                  [trace containsString:@"phase deferred: temporary jailbreakd termination to launchd userspace teardown"];
            if (!jailbreakdDispositionRecorded) {
                return @"诊断结论：launchd 已收到 RB2_USERREBOOT，但没有记录临时 jailbreakd 的重启处理策略。";
            }
            if (![trace containsString:@"RB2_USERREBOOT forwarding decision"]) {
                return @"诊断结论：launchd 已收到 RB2_USERREBOOT，但没有记录消息转发判定；中断发生在 RootHide XPC Hook 返回系统处理之前。";
            }
            if ([trace containsString:@"RB2_USERREBOOT forwarding decision"] &&
                [trace containsString:@"consumed=1"]) {
                return @"诊断结论：RootHide 的 XPC/JBServer Hook 消费了 RB2_USERREBOOT；请查看 forwarding decision 行。";
            }
            BOOL transitionCallObserved = [trace containsString:@"[launchd] post-RB2_USERREBOOT spawn observation"] ||
                                          [trace containsString:@"[launchd] post-RB2_USERREBOOT execve observation"];
            if (!transitionCallObserved) {
                if ([trace containsString:@"[launchd] kern.willuserspacereboot entered"] &&
                    ![trace containsString:@"[launchd] kern.willuserspacereboot returned"]) {
                    return @"诊断结论：launchd 已调用 kern.willuserspacereboot，但该 sysctl 尚未返回；中断点已缩小到 userspace teardown 的入口。";
                }
                if ([trace containsString:@"[launchd] kern.willuserspacereboot returned"]) {
                    return @"诊断结论：launchd 已正式进入 userspace teardown，但停在 self-spawn/self-exec 之前；问题在某个服务或子进程的退出阶段。";
                }
                if (watchdogRebootXPCObserved) {
                    return @"诊断结论：Apple 重启宿主发出的 RB2_USERREBOOT 已由 launchd 接收且权限验证通过，但尚未进入 kern.willuserspacereboot；剩余故障位于 iOS 18 launchd 的内部 teardown。";
                }
                return @"诊断结论：jbctl preflight 已通过、临时 jailbreakd 由系统 teardown 接管、RB2_USERREBOOT 也已转交；但 launchd 仍未开始 self-spawn/self-exec。";
            }
            return @"诊断结论：launchd 已收到 RB2_USERREBOOT，并调用了进程替换 API，但目标没有匹配当前 launchd；请查看 post-RB2_USERREBOOT 与 candidate 行。";
        }
        if (replacementMatched) {
            BOOL primitivesStashed = [trace containsString:@"[boomerang] phase complete: primitives stashed for userspace reboot"] ||
                                     [trace containsString:@"[boomerang] primitives already stashed in live handoff process"];
            if (!primitivesStashed) {
                return @"诊断结论：已匹配 launchd 自替换路径，但 boomerang 没有确认 primitive 保存完成。";
            }
            return @"诊断结论：旧 launchd 已完成自替换前的 primitive 保存，但新 launchd 没加载 launchdhook；问题位于环境继承或新进程装载阶段。";
        }
        if ([trace containsString:@"[jbctl] calling reboot3 with RB2_USERREBOOT"] &&
            ![trace containsString:@"[jbctl] reboot3 returned"]) {
            return @"诊断结论：preflight 已通过，jbctl 已进入 reboot3 且没有返回，但新 launchd 构造函数仍未进入。";
        }
        return @"诊断结论：preflight 已通过，但用户空间重启没有进入新的 launchd；以最后一条 jbctl、XPC、spawn 或 execve 日志为准。";
    }

    if ([trace containsString:@"phase: gathering system information"] && ![trace containsString:@"phase complete: gathering system information"]) {
        return @"诊断结论：卡在系统信息或内核偏移准备阶段；请以最后一条日志为准。";
    }
    if ([trace containsString:@"phase: acquiring kernel exploit"] && ![trace containsString:@"phase complete: acquiring kernel exploit"]) {
        return @"诊断结论：卡在内核漏洞获取阶段；这发生在 RootHide 初始化之前。";
    }
    if ([trace containsString:@"phase: building physical read/write primitive"] && ![trace containsString:@"phase complete: building physical read/write primitive"]) {
        return @"诊断结论：漏洞已获取，但卡在构建内核读写原语阶段。";
    }
    if ([trace containsString:@"phase: elevating privileges"] && ![trace containsString:@"phase complete: elevating privileges"]) {
        return @"诊断结论：停在提权阶段；以最后一条 elevate: 日志为准。";
    }
    if ([trace containsString:@"phase: preparing RootHide bootstrap"] && ![trace containsString:@"phase complete: preparing RootHide bootstrap"]) {
        return @"诊断结论：卡在 RootHide Bootstrap 文件准备阶段，尚未进入 BaseBin TrustCache 或 launchd 注入。";
    }
    if ([trace containsString:@"phase: generating RootHide dyld environment"] &&
        ![trace containsString:@"phase complete: generating RootHide dyld environment"]) {
        NSRange mergerRange = [trace rangeOfString:@"/basebin/MachOMerger" options:NSBackwardsSearch];
        NSString *mergerTrace = mergerRange.location == NSNotFound ? @"" : [trace substringFromIndex:mergerRange.location];
        BOOL mergerResumed = [mergerTrace containsString:@"resumed unpatched child"];
        BOOL waitCompleted = [mergerTrace containsString:@"child wait completed"];
        if (mergerResumed && !waitCompleted) {
            return @"诊断结论：MachOMerger 已启动并恢复运行，但父进程没有观察到它退出；当前流程尚未注入 launchd，故障已隔离到 MachOMerger 或输入 dyld。";
        }
        if (waitCompleted) {
            return @"诊断结论：MachOMerger 已退出，但 RootHide dyld 生成流程没有完成；请查看最后一条 child wait completed 的退出码或信号。";
        }
        return @"诊断结论：停在 RootHide dyld 生成阶段；MachOMerger 尚未完成 spawn/resume。";
    }
    if ([trace containsString:@"FAILURE: opainject returned"]) {
        return @"诊断结论：opainject 已返回错误。错误码见上一行，launchdhook 没有完成启动。";
    }
    if (![trace containsString:@"[launchd] constructor entered"]) {
        return @"诊断结论：opainject 已开始向 launchd 注入，但 launchdhook 构造函数没有进入。中断点在 ROP dlopen 调用内部。";
    }
    if (![trace containsString:@"phase complete: boomerang primitive recovery"]) {
        return @"诊断结论：launchdhook 已进入，但在把内核原语从 Dopamine 交接给 launchd 的阶段中断。";
    }
    if (![trace containsString:@"phase complete: jetsam hooks"]) {
        return @"诊断结论：内核原语已交接；失败发生在 Dopamine 原生 launchd hook 初始化期间。最后一个“phase complete”即最后成功阶段。";
    }
    if ([trace containsString:@"FAILURE: could not install systemhook"]) {
        return @"诊断结论：RootHide 无法把 systemhook 安装到 /usr/lib。";
    }
    if ([trace containsString:@"FAILURE: jailbreakd initialization returned"]) {
        return @"诊断结论：RootHide jailbreakd 启动失败，返回码见上一行。";
    }
    if ([trace containsString:@"[jailbreakd] phase: initializing jailbreak primitives"] &&
        ![trace containsString:@"[jailbreakd] jailbreak primitive initialization returned"]) {
        if ([trace containsString:@"[primitive] requesting system information from launchd"] &&
            ![trace containsString:@"[primitive] system information request returned"]) {
            if ([trace containsString:@"[launchd] direct jailbreakd bootstrap message"] &&
                ![trace containsString:@"[launchd] direct jailbreakd bootstrap handler returned"]) {
                return @"诊断结论：jailbreakd 的 sysinfo 消息已到达专用端口，但 RootHide 全局 jbserver 处理器没有返回。";
            }
            if ([trace containsString:@"[launchd] direct jailbreakd bootstrap handler returned 0"]) {
                return @"诊断结论：launchd 已处理并回复 jailbreakd 的 sysinfo 请求，但回复没有送回客户端。";
            }
            return @"诊断结论：临时 jailbreakd 已启动，但向 launchd 请求系统信息的 XPC 调用没有返回。";
        }
        if ([trace containsString:@"[primitive] requesting PTE physrw handoff from launchd"] &&
            ![trace containsString:@"[primitive] physrw handoff returned"]) {
            return @"诊断结论：系统信息已收到，但 launchd 在为临时 jailbreakd 建立 PTE 内核读写窗口时没有返回。";
        }
        if ([trace containsString:@"[primitive] requesting full physrw handoff from launchd"] &&
            ![trace containsString:@"[primitive] physrw handoff returned"]) {
            return @"诊断结论：系统信息已收到，但 launchd 卡在完整物理内存映射；iOS 18 首次启动应使用 PTE handoff。";
        }
        if ([trace containsString:@"[primitive] physrw handoff returned 0"] &&
            ![trace containsString:@"[primitive] local physrw initialization returned"]) {
            return @"诊断结论：内核读写映射已经交接，但 jailbreakd 未完成本地 primitive 安装。";
        }
        if ([trace containsString:@"[primitive] initializing address translation"] &&
            ![trace containsString:@"[primitive] address translation initialized"]) {
            return @"诊断结论：PTE/physrw 已安装，但 jailbreakd 卡在内核地址转换初始化。";
        }
        if ([trace containsString:@"[primitive] address translation initialized; initializing IOSurface primitives"] &&
            ![trace containsString:@"[primitive] IOSurface primitives initialized"]) {
            return @"诊断结论：PTE/physrw 已可用，但 jailbreakd 卡在 IOSurface primitive 初始化。";
        }
        if ([trace containsString:@"[primitive] initializing Fugu14 kcall"] &&
            ![trace containsString:@"[primitive] Fugu14 kcall initialization returned"]) {
            return @"诊断结论：物理读写与 IOSurface 已可用，但 jailbreakd 卡在 Fugu14 kcall 初始化。";
        }
        if ([trace containsString:@"[primitive] initializing arm64 kcall"] &&
            ![trace containsString:@"[primitive] arm64 kcall initialization returned"]) {
            return @"诊断结论：物理读写与 IOSurface 已可用，但 jailbreakd 卡在 arm64 kcall 初始化。";
        }
        if ([trace containsString:@"[primitive] primitive initialization complete"]) {
            return @"诊断结论：内核原语内部初始化已完成，但控制流没有返回 jailbreakd 主启动函数。";
        }
        return @"诊断结论：临时 jailbreakd 已启动，但内核原语初始化没有返回；以最后一条 primitive 日志为准。";
    }
    if ([trace containsString:@"phase: RootHide post-initialization"] && ![trace containsString:@"phase complete: RootHide post-initialization"]) {
        return @"诊断结论：Dopamine 原生 launchd hook 已完成；失败发生在 RootHide 服务初始化。";
    }
    if (![trace containsString:@"phase complete: launchd primitive-handoff acknowledgement received"]) {
        return @"诊断结论：launchd 已继续执行，但 Dopamine 没有收到原语交接确认。请以最后一条日志为准。";
    }
    return @"诊断结论：启动流程已通过已记录阶段；请分享完整日志以确认用户空间重启后的后续状态。";
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];

    if (self.didPresentRootHideTrace || [[DOEnvironmentManager sharedManager] isJailbroken]) return;

    NSString *tracePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/RootHideLaunchdTrace.log"];
    NSString *trace = [NSString stringWithContentsOfFile:tracePath encoding:NSUTF8StringEncoding error:nil];
    if (![trace containsString:@"RootHide jailbreak diagnostic trace"]) return;
    if ([[[NSUserDefaults standardUserDefaults] stringForKey:RootHideLastPresentedTraceKey] isEqualToString:trace]) return;

    self.didPresentRootHideTrace = YES;
    [[NSUserDefaults standardUserDefaults] setObject:trace forKey:RootHideLastPresentedTraceKey];
    NSMutableArray<NSString *> *traceLines = [NSMutableArray array];
    for (NSString *line in [trace componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if (line.length > 0) [traceLines addObject:line];
    }
    [traceLines addObject:[self rootHideTraceDiagnosisForTrace:trace]];
    [DOUIManager sharedInstance].logRecord = traceLines;
    [self.navigationController pushViewController:[[DOLogCrashViewController alloc] initWithTitle:@"RootHide 启动诊断" exitOnDisappear:NO] animated:YES];
}

- (void)startJailbreak
{
    DOJailbreaker *jailbreaker = [[DOJailbreaker alloc] init];

    [[DOUIManager sharedInstance] startLogCapture];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        if ([jailbreaker contiguousMappingWorkaroundNeeded]) {
            
            cpu_subtype_t cpuFamily = 0;
            size_t cpuFamilySize = sizeof(cpuFamily);
            sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
            NSString *workaroundMessage = DOLocalizedString(@"Respring_Required_Message");
            if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
                workaroundMessage = [workaroundMessage stringByAppendingString:[NSString stringWithFormat:@"\n\n%@", DOLocalizedString(@"Respring_Required_Notice_A8")]];
            }

            UIAlertController *contiguousMappingWorkaroundAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Respring_Required") message:workaroundMessage preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Respring_Cancel") style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                exit(0);
            }];
            
            UIAlertAction *workaroundAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Apply_Workaround") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                [jailbreaker applyContiguousMappingWorkaround];
            }];
            
            [contiguousMappingWorkaroundAlertController addAction:cancelAction];
            [contiguousMappingWorkaroundAlertController addAction:workaroundAction];
            contiguousMappingWorkaroundAlertController.preferredAction = workaroundAction;

            dispatch_async(dispatch_get_main_queue(), ^{
                [self presentViewController:contiguousMappingWorkaroundAlertController animated:YES completion:nil];
            });
            return;
        }

        //We need to get the preconfig mutex to start the jailbreak (self.jailbreakBtn.canStartJailbreak)
        [self.jailbreakBtn lockMutex];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.hideHomeIndicator = YES;
        });

        NSError *error;
        BOOL didRemove = NO;
        BOOL showLogs = YES;
        [jailbreaker runWithError:&error didRemoveJailbreak:&didRemove showLogs:&showLogs];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error && showLogs) {
                [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Jailbreak failed with error: %@", error] debug:NO];
                [self.navigationController pushViewController:[[DOLogCrashViewController alloc] initWithTitle:[error localizedDescription]] animated:YES];
            }
            else if (error && !showLogs) {
                // Used when there is an error that is explainable in such detail that additional logs are not needed
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error") message:[error localizedDescription] preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Reboot") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exec_cmd_trusted(JBROOT_PATH("/sbin/reboot"), NULL);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else if (didRemove) {
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Removed_Jailbreak_Alert_Title") message:DOLocalizedString(@"Removed_Jailbreak_Alert_Message") preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Close") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exit(0);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else {
                // No errors
                [[DOUIManager sharedInstance] completeJailbreak];
                [self fadeToBlack: ^{
                    [jailbreaker finalize];
                }];
            }
        });
        [self.jailbreakBtn unlockMutex];
    });
}

-(void)setupUpdateAvailable:(BOOL)environmentUpdate
{
    if (self.jailbreakBtn.didExpand)
        return;

    NSString *title = environmentUpdate ? DOLocalizedString(@"Button_Update_Environment") : DOLocalizedString(@"Button_Update_Available");
    
    NSString *releaseFrom = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    NSString *releaseTo = [[DOUIManager sharedInstance] getLatestReleaseTag];

    if (environmentUpdate)
    {
        releaseFrom = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
        releaseTo = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    }

    self.updateButton = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:title image:[UIImage systemImageNamed:@"arrow.down.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"update-available" handler:^(__kindof UIAction * _Nonnull action) {
        [self.navigationController pushViewController:[[DOUpdateViewController alloc] initFromTag:releaseFrom toTag:releaseTo] animated:YES];
    }] chevron:NO];

    self.updateButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.updateButton];

    [NSLayoutConstraint activateConstraints:@[
        [self.updateButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.updateButton.heightAnchor constraintEqualToConstant:30],
        [self.updateButton.bottomAnchor constraintEqualToAnchor:self.jailbreakBtn.topAnchor constant:[DOGlobalAppearance isHomeButtonDevice] ? -10 : -20]
    ]];

    [self.updateButton setTransform:CGAffineTransformMakeTranslation(0, 25)];
    [self.updateButton setAlpha:0];
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
        [self.updateButton setTransform:CGAffineTransformIdentity];
        [self.updateButton setAlpha:1];
    } completion:nil];
}

-(void)simulateJailbreak
{
    // Let's simulate a "jailbreak" using grand central dispatch

    DOUIManager *uiManager = [DOUIManager sharedInstance];

    static BOOL didFinish = NO; //not thread safe lol
    

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [uiManager completeJailbreak];
        [uiManager sendLog:@"Rebooting Userspace" debug: NO];
        didFinish = YES;
        [self fadeToBlack: ^{

        }];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [NSThread sleepForTimeInterval:0.2];
        [uiManager sendLog:@"Launching kexploitd" debug: NO];
        [NSThread sleepForTimeInterval:0.5];
        [uiManager sendLog:@"Launching oobPCI" debug: NO];
        [NSThread sleepForTimeInterval:0.15];
        [uiManager sendLog:@"Gaining r/w" debug: NO];
        [NSThread sleepForTimeInterval:0.8];
        [uiManager sendLog:@"Patchfinding" debug: NO];
        NSArray *types = @[@"AMFI", @"PAC", @"KTRR", @"KPP", @"PPL", @"KPF", @"APRR", @"AMCC", @"PAN", @"PXN", @"ASLR", @"OPA"]; //Ever heard of the legendary opa bypass
        while (true)
        {
            [NSThread sleepForTimeInterval:0.6 * rand() / RAND_MAX];
            if (didFinish) break;
            NSString *type = types[arc4random_uniform((uint32_t)types.count)];
            [uiManager sendLog:[NSString stringWithFormat:@"Bypassing %@", type] debug: NO];
        }
    });
}

- (void)fadeToBlack:(void (^)(void))completion
{
    static bool didFade = false;
    if (didFade)
        return;
    didFade = true;
    UIView *mainView = self.parentViewController.view;
    float deviceCornerRadius = [[[UIScreen mainScreen] valueForKey:@"_displayCornerRadius"] floatValue];

    mainView.layer.cornerRadius = deviceCornerRadius;
    mainView.layer.cornerCurve = kCACornerCurveContinuous;
    mainView.layer.masksToBounds = YES;
    
    self.hideStatusBar = YES;

    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0 options: UIViewAnimationOptionCurveEaseInOut animations:^{
        mainView.transform = CGAffineTransformMakeScale(0.9, 0.9);
        mainView.alpha = 0.0;
    } completion:^(BOOL success) {
        completion();
    }];
}

#pragma mark - Action Menu Delegate

- (BOOL)actionMenuShowsChevronForAction:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"settings"] || [action.identifier isEqualToString:@"credits"]) return YES;
    return NO;
}

- (BOOL)actionMenuActionIsEnabled:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"respring"] || [action.identifier isEqualToString:@"reboot-userspace"]) {
        return [[DOEnvironmentManager sharedManager] isJailbroken];
    }
    return YES;
}

#pragma mark - Status Bar

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return UIStatusBarStyleLightContent;
}

- (BOOL)prefersStatusBarHidden
{
    return self.hideStatusBar;
}

- (BOOL)prefersHomeIndicatorAutoHidden
{
    return self.hideHomeIndicator;
}

- (void)setHideStatusBar:(BOOL)hideStatusBar
{
    _hideStatusBar = hideStatusBar;
    [self setNeedsStatusBarAppearanceUpdate];
}

- (void)setHideHomeIndicator:(BOOL)hideHomeIndicator
{
    _hideHomeIndicator = hideHomeIndicator;
    [self setNeedsUpdateOfHomeIndicatorAutoHidden];
}

@end
