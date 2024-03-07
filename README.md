Development of this project has come to an end. It was being maintained by a few dedicated engineers
from Microsoft outside of their normal work assignments in their spare time. With changing roles and 
responsibilities, they have moved on to other projects and no longer are able to maintain this code. 

The repo will be archived at some time in the future, date to be determined. The code at the time of archive 
while functional, did not handle retired DCs that were offline but had not been completely removed from 
Active Directory. The script generates an error because it cannot reach the offline DC. Newer versions of 
the script that are published elsewhere reportedly address this issue. The offline DC should be removed from 
AD using ntdsutil, see these articles for guidance. 
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/ad-ds-metadata-cleanup
https://techcommunity.microsoft.com/t5/itops-talk-blog/step-by-step-manually-removing-a-domain-controller-server/ba-p/280564


The good news is that there are other coders that have picked up maintaining this code. Some of the other 
resources that you can check are:

https://gist.github.com/mubix/fd0c89ec021f70023695

https://github.com/zjorz/Public-AD-Scripts/blob/5666e5fcafd933c3288a47944cd6fb289dde54a1/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1






This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
