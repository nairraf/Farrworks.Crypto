using NUnit.Framework;
using System.Collections;

namespace Farrworks.Crypto.Tests.Data
{
    public class EncryptDecryptTestData
    {
        public static IEnumerable TestCases
        {
            get
            {
                yield return new TestCaseData("This is a test");
                yield return new TestCaseData("thisIsMyPassword");
                yield return new TestCaseData(@"this is a test to TestAnotherLongerSentence and with some special characters:`~!@#$%^&*()-_=+\|]}[{';:/?.>,< The End");
                yield return new TestCaseData("10.210.32.245");
                yield return new TestCaseData("192.168.200.72/24");
                yield return new TestCaseData("ALL UPPERCASE");
                yield return new TestCaseData("all lowercase");
                yield return new TestCaseData("a");
                yield return new TestCaseData(@"1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM`~!@#$%^&*()-_=+\|]}[{';:/?.>,<0123456789/*-+.");
                yield return new TestCaseData(@"
                    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer justo eros, egestas non ligula nec, viverra ultricies magna. Integer luctus, est id egestas sagittis, dolor nisl consectetur sapien, quis suscipit massa lectus in augue. Fusce in tortor in sapien posuere sollicitudin eu sed massa. Phasellus ornare purus velit. Suspendisse nunc purus, ullamcorper a molestie at, maximus ac ipsum. Suspendisse nec volutpat arcu. Fusce egestas ornare luctus. Nulla egestas vestibulum lectus, vitae consequat turpis feugiat id. Aenean pharetra, neque nec egestas porta, lorem lorem molestie neque, quis suscipit ipsum urna quis nisl. Morbi pellentesque venenatis libero, nec posuere est dictum sit amet. Suspendisse potenti. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus.
                    Nulla non magna lobortis, bibendum augue sit amet, scelerisque lacus. Quisque luctus augue vel libero varius gravida. Nullam eget nunc vitae sem pellentesque efficitur at interdum neque. Curabitur mollis ex quis nunc suscipit auctor. Morbi in lorem nec nulla volutpat hendrerit in elementum arcu. Aliquam eget ante dui. Pellentesque mattis lacus ut viverra auctor. In nec enim sed nibh malesuada rutrum vel eget urna. Mauris scelerisque mauris nisi, scelerisque vulputate ex hendrerit ut. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Mauris laoreet lectus urna, id convallis ex ultrices vel. Suspendisse potenti. Suspendisse vestibulum lacus non tristique venenatis. Pellentesque sit amet justo eget ligula placerat volutpat ac quis metus. Nam eu viverra quam. Aliquam ac ornare est, vel pulvinar nibh.
                ");
            }
        }
    }
}
