using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace RbacNet.Core
{
    public class Authorization
    {
        public Authorization(Claim claim, Item item)
        {
            this.Claim = claim;
            this.Item = item;
        }
        public Item Item { get; private set; }
        public Claim Claim { get; private set; }
    }
    public interface Item
    {
        string Name { get; }

        IEnumerable<Operation> GetOperations();
    }
    public struct Role : Item
    {
        public Role(string name)
        {
            Name = name;
            Operations = new HashSet<Operation>();
            Tasks = new HashSet<Task>();
            Roles = new HashSet<Role>();

        }
        public string Name { get; set; }
        public ISet<Role> Roles { get; private set; }
        public ISet<Task> Tasks { get; private set; }
        public ISet<Operation> Operations { get; private set; }

        public IEnumerable<Operation> GetOperations()
        {
            return Roles
                .SelectMany(r => r.Tasks).Union(Tasks)
                .SelectMany(t => t.Operations).Union(Operations);
        }
        public override string ToString()
        {
            return Name;
        }
    }
    public struct Task : Item
    {
        public Task(string name)
        {
            Name = name;
            Operations = new HashSet<Operation>();
        }
        public string Name { get; private set; }
        public ISet<Operation> Operations { get; private set; }
        public IEnumerable<Operation> GetOperations()
        {
            return Operations;
        }
        public override string ToString()
        {
            return Name;
        }
    }
    public struct Operation : Item
    {
        public Operation(string name)
        {
            Name = name;
        }
        public string Name { get; set; }

        public IEnumerable<Operation> GetOperations()
        {
            return Enumerable.DefaultIfEmpty(Enumerable.Empty<Operation>(), this);
        }

        public override string ToString()
        {
            return Name;
        }
    }
    public class Rbac
    {
        private class ClaimEqualityComparer : EqualityComparer<Claim>
        {
            private static readonly EqualityComparer<Claim> instance = new ClaimEqualityComparer();

            public static EqualityComparer<Claim> Instance => instance;

            public override bool Equals(Claim x, Claim y)
            {
                return x?.Type == y?.Type && x.ValueType == y.ValueType && x.Value == y.Value;
            }

            public override int GetHashCode(Claim obj)
            {
                unchecked
                {
                    int hash = 17;
                    hash = hash * 23 + obj.Type.GetHashCode();
                    hash = hash * 23 + obj.ValueType.GetHashCode();
                    hash = hash * 23 + obj.Value.GetHashCode();
                    return hash;
                }
            }
        }

        private readonly HashSet<Role> roles = new HashSet<Role>();
        private readonly List<Authorization> allowAuthorizations = new List<Authorization>();
        private readonly List<Authorization> denyAuthorizations = new List<Authorization>();

        public Rbac()
        {

        }

        public Rbac Add(params Role[] roles)
        {
            AddRoles(roles);
            return this;
        }
        public Rbac Allow(params Authorization[] authorizations)
        {
            this.allowAuthorizations.AddRange(authorizations);

            return this;
        }
        public Rbac Deny(params Authorization[] authorizations)
        {
            this.denyAuthorizations.AddRange(authorizations);
            return this;
        }

        private void AddRoles(IEnumerable<Role> roles)
        {
            foreach (var role in roles)
            {
                this.roles.Add(role);
            }
        }

        public UserAuhorizationContext GetContextFor(ClaimsIdentity identity)
        {
            var allowedOperations = GetAuthorizedOperations(allowAuthorizations, identity.Claims);
            var deniedOperations = GetAuthorizedOperations(denyAuthorizations, identity.Claims);

            return new UserAuhorizationContext(allowedOperations.Except(deniedOperations));
        }

        private static IEnumerable<Operation> GetAuthorizedOperations(IEnumerable<Authorization> authorizations, IEnumerable<Claim> identityClaims)
        {
            return authorizations
                .Where(c => identityClaims.Contains(c.Claim, ClaimEqualityComparer.Instance))
                .SelectMany(c => c.Item.GetOperations())
                .Distinct();
        }
    }
    public class UserAuhorizationContext
    {
        private ISet<Operation> allowedOperations;

        public UserAuhorizationContext(IEnumerable<Operation> allowedOperations)
        {
            this.allowedOperations = new HashSet<Operation>(allowedOperations);
        }
        public bool CanPerform(Operation operation)
        {
            return allowedOperations.Contains(operation);

        }
    }
}
