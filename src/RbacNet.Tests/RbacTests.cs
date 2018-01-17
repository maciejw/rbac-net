using System;
using Xunit;

namespace RbacNet.Tests
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using Core;

    namespace Application
    {
        class Operations
        {
            public static readonly Operation Operation1 = new Operation(nameof(Operation1));
            public static readonly Operation Operation2 = new Operation(nameof(Operation2));
            public static readonly Operation Operation3 = new Operation(nameof(Operation3));
            public static readonly Operation Operation4 = new Operation(nameof(Operation4));
            public static readonly Operation Operation5 = new Operation(nameof(Operation5));
            public static readonly Operation Operation6 = new Operation(nameof(Operation6));
            public static readonly Operation Operation7 = new Operation(nameof(Operation7));
        }
        class Tasks
        {
            public static readonly Task Task1 = new Task(nameof(Task1))
            {
                Operations = { Operations.Operation1, Operations.Operation3 }
            };
            public static readonly Task Task2 = new Task(nameof(Task2))
            {
                Operations = { Operations.Operation4, Operations.Operation5, Operations.Operation6 }
            };
            public static readonly Task Task3 = new Task(nameof(Task3))
            {
                Operations = { Operations.Operation2, Operations.Operation7 }
            };
        }
        class Roles
        {
            public static readonly Role Role1 = new Role(nameof(Role1))
            {
                Tasks = { Tasks.Task2 }
            };

            public static readonly Role Role2 = new Role(nameof(Role2))
            {
                Roles = { Role1 },
                Tasks = { Tasks.Task1 }
            };
            public static readonly Role Role3 = new Role(nameof(Role3))
            {
                Tasks = { Tasks.Task3 },
                Operations = { Operations.Operation4 }
            };
        }
    }

    class Security
    {
        public class ActorClaims
        {
            public static readonly Claim Name1 = new Claim(ClaimTypes.Actor, "Name1");
            public static readonly Claim Name2 = new Claim(ClaimTypes.Actor, "Name2");
            public static readonly Claim Name3 = new Claim(ClaimTypes.Actor, "Name3");
            public static readonly Claim Name4 = new Claim(ClaimTypes.Actor, "Name4");
        }
        public class MembershipClaims
        {
            public static readonly Claim Group1 = new Claim(ClaimTypes.GroupSid, "Group1");
            public static readonly Claim Group2 = new Claim(ClaimTypes.GroupSid, "Group2");
            public static readonly Claim Group3 = new Claim(ClaimTypes.GroupSid, "Group3");
        }
        public static readonly ClaimsIdentity User1 = new ClaimsIdentity(new[]
        {
            ActorClaims.Name1,
            MembershipClaims.Group1
        });
        public static readonly ClaimsIdentity User2 = new ClaimsIdentity(new[]
        {
            ActorClaims.Name2,
            MembershipClaims.Group1
        });
        public static readonly ClaimsIdentity User3 = new ClaimsIdentity(new[]
        {
            ActorClaims.Name3,
            MembershipClaims.Group2
        });
        public static readonly ClaimsIdentity User4 = new ClaimsIdentity(new[]
        {
            ActorClaims.Name4,
            MembershipClaims.Group3
        });
        public static Authorization[] GetDenyAuthorizations()
        {
            return new[]{
                (Actor: Security.ActorClaims.Name2, Operation: Application.Operations.Operation4 ),
                (Actor: Security.ActorClaims.Name3, Operation: Application.Operations.Operation5 ),
             }.Select(p => new Authorization(p.Actor, p.Operation)).ToArray();
        }

        public static Authorization[] GetAllowAuthorizations()
        {
            return new[] {
                (Group: Security.MembershipClaims.Group1, Role: Application.Roles.Role1),
                (Group: Security.MembershipClaims.Group2, Role: Application.Roles.Role2),
                (Group: Security.MembershipClaims.Group3, Role: Application.Roles.Role3),
             }.Select(p => new Authorization(p.Group, p.Role)).ToArray();
        }

    }
    public class RbacTests
    {
        private readonly Func<ClaimsIdentity, UserAuhorizationContext> GetContextFor;

        public RbacTests()
        {
            GetContextFor = new Rbac()
                .Add(Application.Roles.Role1)
                .Add(Application.Roles.Role2)
                .Add(Application.Roles.Role3)
                .Allow(Security.GetAllowAuthorizations())
                .Deny(Security.GetDenyAuthorizations())
                .GetContextFor;
        }
        [Theory]
        [MemberData(nameof(User_should_be_able_to_perform_an_operations_data))]
        public void User_should_be_able_to_perform_an_operations(ClaimsIdentity User, (Operation Operation, bool ExpectedResult)[] Operations)
        {
            foreach (var @case in Operations)
            {
                var actual = GetContextFor(User).CanPerform(@case.Operation);

                Assert.Equal(@case.ExpectedResult, actual);
            }
        }

        public static IEnumerable<object[]> User_should_be_able_to_perform_an_operations_data()
        {
            yield return new object[] { Security.User1, new[] {
                (Operation: Application.Operations.Operation1, ExpectedResult: false),
                (Operation: Application.Operations.Operation2, ExpectedResult: false),
                (Operation: Application.Operations.Operation3, ExpectedResult: false),
                (Operation: Application.Operations.Operation4, ExpectedResult: true),
                (Operation: Application.Operations.Operation5, ExpectedResult: true),
                (Operation: Application.Operations.Operation6, ExpectedResult: true),
                (Operation: Application.Operations.Operation7, ExpectedResult: false),
            }};

            yield return new object[] { Security.User2, new[] {
                (Operation: Application.Operations.Operation1, ExpectedResult: false),
                (Operation: Application.Operations.Operation2, ExpectedResult: false),
                (Operation: Application.Operations.Operation3, ExpectedResult: false),
                (Operation: Application.Operations.Operation4, ExpectedResult: false),
                (Operation: Application.Operations.Operation5, ExpectedResult: true),
                (Operation: Application.Operations.Operation6, ExpectedResult: true),
                (Operation: Application.Operations.Operation7, ExpectedResult: false),
            }};
            yield return new object[] { Security.User3, new[] {
                (Operation: Application.Operations.Operation1, ExpectedResult: true),
                (Operation: Application.Operations.Operation2, ExpectedResult: false),
                (Operation: Application.Operations.Operation3, ExpectedResult: true),
                (Operation: Application.Operations.Operation4, ExpectedResult: true),
                (Operation: Application.Operations.Operation5, ExpectedResult: false),
                (Operation: Application.Operations.Operation6, ExpectedResult: true),
                (Operation: Application.Operations.Operation7, ExpectedResult: false),
            }};
            yield return new object[] { Security.User4, new[] {
                (Operation: Application.Operations.Operation1, ExpectedResult: false),
                (Operation: Application.Operations.Operation2, ExpectedResult: true),
                (Operation: Application.Operations.Operation3, ExpectedResult: false),
                (Operation: Application.Operations.Operation4, ExpectedResult: true),
                (Operation: Application.Operations.Operation5, ExpectedResult: false),
                (Operation: Application.Operations.Operation6, ExpectedResult: false),
                (Operation: Application.Operations.Operation7, ExpectedResult: true),
            }};
        }

    }
}
